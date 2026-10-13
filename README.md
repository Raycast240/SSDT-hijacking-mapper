# mapper

A Windows kernel driver mapper that loads unsigned drivers by executing them inside ntoskrnl.exe's address space via SSDT hijacking.

## How it works

The mapper requires a vulnerable driver exposing physical memory read/write (the default target is `EBIoDispatch`). It performs the following steps:

1. **Service installation** — Installs the vulnerable driver as a kernel service with a randomized name, enabling `SeLoadDriverPrivilege`.

2. **Symbol resolution** — Uses PDB parsing (via `g_pdb`) to locate critical kernel symbols: `PiDDBLock`, `PiDDBCacheTable`, `KeServiceDescriptorTable`, `ExAcquireResourceExclusiveLite`, `ExReleaseResourceLite`, `RtlLookupElementGenericTableAvl`, `RtlDeleteElementGenericTableAvl`, plus various `Mm*` and `EPROCESS`/`KPROCESS`/`MMPFN` offsets.

3. **Paging setup** — Establishes a paging context to translate virtual addresses to physical addresses using `MmGetPhysicalAddress`.

4. **SSDT hijack** — Locates `NtWriteVirtualMemory` in both `KeServiceDescriptorTable` and `KeServiceDescriptorTableShadow`. Overwrites the SSDT entry to redirect execution to a controlled kernel address. The hijack is verified before and after each use, with automatic restoration on teardown.

5. **Cave allocation** — Allocates a large-page memory region inside ntoskrnl.exe's image range using `MmAllocateIndependentPages`. The target driver image must fit within this range.

6. **Image preparation** — Parses the target PE, applies base relocations, resolves imports and delayed imports against loaded kernel modules, and copies sections into a local buffer.

7. **Physical write** — Writes the prepared image page-by-page to the allocated cave via the vulnerable driver's physical memory write primitive.

8. **Entry execution** — Builds an entry context containing resolved kernel symbols and structure offsets, allocates it in independent pages, then invokes the driver's `DriverEntry` through the hijacked `NtWriteVirtualMemory` syscall. The SSDT is restored immediately after.

9. **Cleanup** — Restores SSDT entries, frees allocated pages, unloads the vulnerable driver service.

## Requirements

- Windows 10 1903+ (tested up to 24H2/25H2)
- A vulnerable driver providing physical memory read/write via IOCTL (default: `EBIoDispatch`, IOCTLs `0x22E008` / `0x22E00C`)
- PDBs for the target OS build (ntoskrnl.exe, optionally ntdll.dll)
- Administrator privileges

## Building

Open `mapper.slnx` in Visual Studio 2022. The project is configured for x64 Release. Dependencies are included in `vendor/`.

## Usage

```
mapper.exe <path_to_driver.sys>
```

The driver must be a valid PE32+ image with relocations (not stripped). Imports must resolve to currently loaded kernel modules.

## Supported OS builds

- 19041 (2004) through 19045 (22H2): classic inline page-table decode
- 22000 (21H2) through 26100 (24H2/25H2): buddy callable (`MiGetPageTablePfnBuddyRaw`) or inline PID-safe decode

The mapper detects the OS build and selects the appropriate page-table walk strategy automatically.

## Architecture overview

```
entry.cpp                 — main flow, orchestration
core/
  gate.hpp                — SSDT hijack, syscall invocation, slot encoding/decoding
  phys.hpp                — VA to PA translation via MmGetPhysicalAddress
  krnl.hpp                — kernel module enumeration, export resolution
  ntexp.hpp               — PDB symbol/structure parsing
load/
  payload.hpp             — PE parsing, section/reloc/import access
  image.hpp               — mapping logic: relocate, import, section copy, physical write
  import.hpp              — buddy callable resolution, inline decode patterns
boot/
  bringup.hpp             — vulnerable driver service install
  device.hpp              — driver communication, physical memory map/unmap, syscall stub
  residual/               — post-load cleanup (PiDDB cache, unload, sweep, snap, filter, cache)
```

## Notes

- The SSDT hijack targets `NtWriteVirtualMemory` specifically because its syscall stub is accessible from user mode and its SSDT slot is reliably locatable across builds.
- All kernel memory operations go through the vulnerable driver's physical memory primitives; no direct kernel shellcode execution occurs outside the hijacked syscall.
- The mapper avoids pool allocations for the mapped image, using large pages inside ntoskrnl to reduce detection surface.
- Symbol resolution depends on PDB availability; missing symbols will cause the mapper to abort with a log message.

## License

No license. Use at your own risk.
