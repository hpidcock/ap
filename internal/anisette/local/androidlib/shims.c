// Host-side implementations of the handful of bionic symbols Apple's ADI libraries
// import. Most map straight onto glibc (the x86_64 / aarch64 kernel ABIs agree on
// struct stat, open flags, etc.); the rest are small stubs, mirroring Dadoum/Provision's
// symbol table.
#define _GNU_SOURCE
#include "shims.h"
#include "_cgo_export.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static int shim_system_property_get(const char *name, char *value) {
	(void)name;
	static const char str[] = "no s/n number";
	memcpy(value, str, sizeof(str));
	return (int)(sizeof(str) - 1);
}

static unsigned int shim_arc4random(void) {
	unsigned int v = 0;
	if (getrandom(&v, sizeof v, 0) != (ssize_t)sizeof v) {
		v = (unsigned int)random();
	}
	return v;
}

static int shim_empty_stub(void) { return 0; }

static int *shim_errno(void) { return &errno; }

static void *shim_dlopen(const char *name, int flags) {
	(void)flags;
	return goDlopen((char *)name);
}

static void *shim_dlsym(void *handle, const char *name) {
	return goDlsym(handle, (char *)name);
}

static int shim_dlclose(void *handle) {
	goDlclose(handle);
	return 0;
}

// Variadic libc functions need an explicit forwarder with the fixed signature the
// Android code uses.
static int shim_open(const char *path, int flags, int mode) {
	return open(path, flags, mode);
}

static int shim_fstat(int fd, struct stat *st) { return fstat(fd, st); }
static int shim_lstat(const char *p, struct stat *st) { return lstat(p, st); }

void androidlib_trap(void) {
	fprintf(stderr, "ap anisette: Android library called an unresolved import; aborting\n");
	abort();
}

void *androidlib_trap_address(void) { return (void *)&androidlib_trap; }

struct entry {
	const char *name;
	void *ptr;
};

void *androidlib_lookup(const char *name) {
	static const struct entry table[] = {
		{"open", (void *)&shim_open},
		{"dlsym", (void *)&shim_dlsym},
		{"dlopen", (void *)&shim_dlopen},
		{"dlclose", (void *)&shim_dlclose},
		{"close", (void *)&close},
		{"umask", (void *)&umask},
		{"pthread_once", (void *)&shim_empty_stub},
		{"chmod", (void *)&chmod},
		{"pthread_create", (void *)&shim_empty_stub},
		{"lstat", (void *)&shim_lstat},
		{"strncpy", (void *)&strncpy},
		{"pthread_mutex_lock", (void *)&shim_empty_stub},
		{"ftruncate", (void *)&ftruncate},
		{"write", (void *)&write},
		{"pthread_rwlock_unlock", (void *)&shim_empty_stub},
		{"pthread_rwlock_destroy", (void *)&shim_empty_stub},
		{"free", (void *)&free},
		{"fstat", (void *)&shim_fstat},
		{"pthread_rwlock_wrlock", (void *)&shim_empty_stub},
		{"__errno", (void *)&shim_errno},
		{"pthread_rwlock_init", (void *)&shim_empty_stub},
		{"pthread_mutex_unlock", (void *)&shim_empty_stub},
		{"pthread_rwlock_rdlock", (void *)&shim_empty_stub},
		{"gettimeofday", (void *)&gettimeofday},
		{"read", (void *)&read},
		{"mkdir", (void *)&mkdir},
		{"malloc", (void *)&malloc},
		{"__system_property_get", (void *)&shim_system_property_get},
		{"arc4random", (void *)&shim_arc4random},
		{"__cxa_atexit", (void *)&shim_empty_stub},
		{"__cxa_finalize", (void *)&shim_empty_stub},
	};
	for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
		if (strcmp(table[i].name, name) == 0) {
			return table[i].ptr;
		}
	}
	return NULL;
}
