#pragma once

//
// This fork branch builds a fully unlocked Sandboxie-Plus:
//   - the driver reports a permanent ETERNAL certificate with all options,
//   - the driver no longer requires caller .sig files,
//   - user-mode signature checks accept our self-built binaries,
//   - online updates are disabled so official binaries cannot replace this build.
//
// The switch is centralized here so the same sources can still be built
// unmodified by simply removing this define.
//

#ifndef SBIE_UNLOCKED
#define SBIE_UNLOCKED 1
#endif
