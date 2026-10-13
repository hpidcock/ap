#ifndef AP_ANDROIDLIB_SHIMS_H
#define AP_ANDROIDLIB_SHIMS_H

#include <stddef.h>

// Resolve an import of an Android library to a host implementation. Returns NULL for
// symbols we do not provide; the loader then binds them to androidlib_trap.
void *androidlib_lookup(const char *name);

// Called when native code jumps through an unresolved import.
void androidlib_trap(void);
void *androidlib_trap_address(void);

#endif
