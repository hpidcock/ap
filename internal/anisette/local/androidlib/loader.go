// Package androidlib is a minimal in-process loader for Android (bionic) shared
// libraries on a glibc host - just enough to run Apple's libstoreservicescore.so /
// libCoreADI.so, which only import a handful of libc symbols. It maps the PT_LOAD
// segments, applies the RELATIVE / GLOB_DAT / JUMP_SLOT / ABS64 relocations against a
// small host symbol table, and exposes the library's exported symbols. Constructors
// (init_array) are deliberately not run, matching Dadoum/Provision.
package androidlib

/*
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include "shims.h"
*/
import "C"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Library is a loaded Android shared object.
type Library struct {
	Path       string
	mapping    []byte
	bias       uintptr // address that ELF vaddr 0 maps to
	alignedMin uintptr // ELF vaddr of mapping[0]
	symbols    map[string]uintptr
	children   []*Library
	handle     unsafe.Pointer // a 1-byte C allocation used as an opaque dlopen handle
	seq        uint64
}

var (
	registryMu sync.Mutex
	registry   = map[unsafe.Pointer]*Library{}
	nextSeq    uint64
	// SearchDir is where bare sonames passed to dlopen are looked up.
	SearchDir string
	// Debug enables relocation diagnostics.
	Debug = os.Getenv("AP_ANDROIDLIB_DEBUG") != ""
)

func pageSize() uintptr { return uintptr(os.Getpagesize()) }

func pageFloor(n uintptr) uintptr { return n &^ (pageSize() - 1) }
func pageCeil(n uintptr) uintptr  { return (n + pageSize() - 1) &^ (pageSize() - 1) }

// Load maps and relocates the library at path.
func Load(path string) (*Library, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 {
		return nil, errors.New("androidlib: only 64-bit libraries are supported")
	}
	if (runtime.GOARCH == "amd64" && f.Machine != elf.EM_X86_64) || (runtime.GOARCH == "arm64" && f.Machine != elf.EM_AARCH64) {
		return nil, fmt.Errorf("androidlib: %s is for %s, not %s", path, f.Machine, runtime.GOARCH)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var minAddr uintptr = ^uintptr(0)
	var maxAddr uintptr
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if uintptr(p.Vaddr) < minAddr {
			minAddr = uintptr(p.Vaddr)
		}
		if end := uintptr(p.Vaddr + p.Memsz); end > maxAddr {
			maxAddr = end
		}
	}
	if maxAddr == 0 {
		return nil, errors.New("androidlib: no PT_LOAD segments")
	}
	alignedMin := pageFloor(minAddr)
	size := int(pageCeil(maxAddr) - alignedMin)
	mapping, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("androidlib: mmap: %w", err)
	}
	lib := &Library{Path: path, mapping: mapping, symbols: map[string]uintptr{}, alignedMin: alignedMin}
	lib.bias = uintptr(unsafe.Pointer(&mapping[0])) - alignedMin
	ok := false
	defer func() {
		if !ok {
			_ = syscall.Munmap(mapping)
		}
	}()

	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Off+p.Filesz > uint64(len(raw)) {
			return nil, errors.New("androidlib: segment beyond end of file")
		}
		dst := uintptr(p.Vaddr) - alignedMin
		copy(mapping[dst:dst+uintptr(p.Filesz)], raw[p.Off:p.Off+p.Filesz])
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("androidlib: dynsym: %w", err)
	}
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF && s.Value != 0 {
			lib.symbols[s.Name] = uintptr(s.Value)
		}
	}

	for _, sec := range f.Sections {
		switch sec.Type {
		case elf.SHT_RELA:
			data, err := sec.Data()
			if err != nil {
				return nil, err
			}
			if err := lib.relocate(f, syms, data); err != nil {
				return nil, err
			}
		case elf.SHT_REL:
			return nil, errors.New("androidlib: REL relocations are not supported (32-bit library?)")
		}
	}

	// Apply the segment protections now that relocations are in place. With pages
	// larger than the ELF's 4 KiB alignment, segments can share a page, so fall back to
	// a single RWX mapping there.
	if pageSize() == 0x1000 {
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD {
				continue
			}
			start := pageFloor(uintptr(p.Vaddr)) - alignedMin
			end := pageCeil(uintptr(p.Vaddr+p.Memsz)) - alignedMin
			prot := 0
			if p.Flags&elf.PF_R != 0 {
				prot |= syscall.PROT_READ
			}
			if p.Flags&elf.PF_W != 0 {
				prot |= syscall.PROT_WRITE
			}
			if p.Flags&elf.PF_X != 0 {
				prot |= syscall.PROT_EXEC
			}
			if err := syscall.Mprotect(mapping[start:end], prot); err != nil {
				return nil, fmt.Errorf("androidlib: mprotect: %w", err)
			}
		}
	} else if err := syscall.Mprotect(mapping, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC); err != nil {
		return nil, fmt.Errorf("androidlib: mprotect: %w", err)
	}

	registryMu.Lock()
	nextSeq++
	lib.seq = nextSeq
	lib.handle = C.malloc(1)
	registry[lib.handle] = lib
	registryMu.Unlock()
	ok = true
	return lib, nil
}

func (l *Library) relocate(f *elf.File, syms []elf.Symbol, data []byte) error {
	trap := uintptr(C.androidlib_trap_address())
	for off := 0; off+24 <= len(data); off += 24 {
		rOff := uintptr(binary.LittleEndian.Uint64(data[off:]))
		info := binary.LittleEndian.Uint64(data[off+8:])
		addend := uintptr(binary.LittleEndian.Uint64(data[off+16:]))
		symIdx := int(info >> 32)
		typ := uint32(info)
		if rOff < l.alignedMin || rOff-l.alignedMin+8 > uintptr(len(l.mapping)) {
			return fmt.Errorf("androidlib: relocation offset %#x outside the image", rOff)
		}
		where := (*uintptr)(unsafe.Pointer(&l.mapping[rOff-l.alignedMin]))

		var kind string
		switch f.Machine {
		case elf.EM_X86_64:
			switch elf.R_X86_64(typ) {
			case elf.R_X86_64_RELATIVE:
				kind = "relative"
			case elf.R_X86_64_GLOB_DAT:
				kind = "glob_dat"
			case elf.R_X86_64_JMP_SLOT:
				kind = "jump_slot"
			case elf.R_X86_64_64:
				kind = "abs"
			default:
				return fmt.Errorf("androidlib: unknown relocation type %s", elf.R_X86_64(typ))
			}
		case elf.EM_AARCH64:
			switch elf.R_AARCH64(typ) {
			case elf.R_AARCH64_RELATIVE:
				kind = "relative"
			case elf.R_AARCH64_GLOB_DAT:
				kind = "glob_dat"
			case elf.R_AARCH64_JUMP_SLOT:
				kind = "jump_slot"
			case elf.R_AARCH64_ABS64:
				kind = "abs"
			default:
				return fmt.Errorf("androidlib: unknown relocation type %s", elf.R_AARCH64(typ))
			}
		default:
			return fmt.Errorf("androidlib: unsupported machine %s", f.Machine)
		}

		if kind == "relative" {
			*where = l.bias + addend
			continue
		}
		var sym elf.Symbol
		if symIdx > 0 && symIdx-1 < len(syms) {
			sym = syms[symIdx-1]
		}
		var target uintptr
		switch {
		case sym.Section != elf.SHN_UNDEF && sym.Value != 0:
			target = l.bias + uintptr(sym.Value)
		default:
			target = l.importAddress(sym.Name)
			if target == trap && Debug {
				log.Printf("androidlib: %s: unresolved import %q (%s)", filepath.Base(l.Path), sym.Name, kind)
			}
		}
		if kind == "jump_slot" {
			*where = target
		} else {
			*where = target + addend
		}
	}
	return nil
}

func (l *Library) importAddress(name string) uintptr {
	if name == "" {
		return uintptr(C.androidlib_trap_address())
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	if p := C.androidlib_lookup(cname); p != nil {
		return uintptr(p)
	}
	return uintptr(C.androidlib_trap_address())
}

// Symbol returns the address of an exported symbol.
func (l *Library) Symbol(name string) (unsafe.Pointer, error) {
	off, ok := l.symbols[name]
	if !ok {
		return nil, fmt.Errorf("androidlib: symbol %q not found in %s", name, filepath.Base(l.Path))
	}
	return unsafe.Pointer(&l.mapping[off-l.alignedMin]), nil
}

// Handle is an opaque value usable as a dlopen handle.
func (l *Library) Handle() unsafe.Pointer { return l.handle }

// Close unmaps the library and any libraries it dlopen'ed.
func (l *Library) Close() error {
	registryMu.Lock()
	if _, ok := registry[l.handle]; ok {
		delete(registry, l.handle)
		C.free(l.handle)
	}
	children := l.children
	l.children = nil
	registryMu.Unlock()
	for _, c := range children {
		_ = c.Close()
	}
	if l.mapping != nil {
		err := syscall.Munmap(l.mapping)
		l.mapping = nil
		return err
	}
	return nil
}

func lookupHandle(h unsafe.Pointer) *Library {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registry[h]
}

// mostRecent is the library a dlopen call is attributed to (the ADI libraries only ever
// dlopen from libstoreservicescore, so the newest root library is the right parent).
func mostRecent() *Library {
	registryMu.Lock()
	defer registryMu.Unlock()
	var best *Library
	for _, l := range registry {
		if best == nil || l.seq > best.seq {
			best = l
		}
	}
	return best
}

//export goDlopen
func goDlopen(name *C.char) unsafe.Pointer {
	path := C.GoString(name)
	if !filepath.IsAbs(path) {
		dir := SearchDir
		if parent := mostRecent(); parent != nil && dir == "" {
			dir = filepath.Dir(parent.Path)
		}
		path = filepath.Join(dir, filepath.Base(path))
	}
	parent := mostRecent()
	lib, err := Load(path)
	if err != nil {
		if Debug {
			log.Printf("androidlib: dlopen(%s) failed: %v", path, err)
		}
		return nil
	}
	if parent != nil {
		registryMu.Lock()
		parent.children = append(parent.children, lib)
		registryMu.Unlock()
	}
	return lib.Handle()
}

//export goDlsym
func goDlsym(handle unsafe.Pointer, name *C.char) unsafe.Pointer {
	lib := lookupHandle(handle)
	if lib == nil {
		return nil
	}
	p, err := lib.Symbol(C.GoString(name))
	if err != nil {
		return nil
	}
	return p
}

//export goDlclose
func goDlclose(handle unsafe.Pointer) {
	if lib := lookupHandle(handle); lib != nil {
		_ = lib.Close()
	}
}
