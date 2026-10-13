# ezzz mapper

A Windows kernel driver mapper for loading unsigned drivers through SSDT hijacking inside `ntoskrnl.exe`.

## How it works
The mapper uses a vulnerable driver for physical memory read/write. The default target is `EBIoDispatch`.

1. **Service installation** — Installs the vulnerable driver as a kernel service under a randomized name and enables `SeLoadDriverPrivilege`.

2. **Symbol resolution** — Uses PDB parsing through `g_pdb` to find the required kernel symbols, including `PiDDBLock`, `PiDDBCacheTable`, `KeServiceDescriptorTable`, and the required memory management functions and structure offsets.

3. **Paging setup** — Sets up virtual-to-physical address translation using `MmGetPhysicalAddress`.

4. **SSDT hijack** — Finds `NtWriteVirtualMemory` in `KeServiceDescriptorTable` and `KeServiceDescriptorTableShadow` and redirects the relevant SSDT entry. The hook is checked before use and restored afterward.

5. **Cave allocation** — Allocates pages inside the `ntoskrnl.exe` image range using `MmAllocateIndependentPages`. The driver image must fit in the allocated region.

6. **Image preparation** — Parses the target PE, applies relocations, resolves imports and delayed imports, and prepares the sections for mapping.

7. **Physical write** — Writes the prepared image page by page through the vulnerable driver's physical memory interface.

8. **Entry execution** — Creates an entry context with the resolved symbols and offsets, then calls `DriverEntry` through the hooked syscall. The original SSDT entry is restored afterward.

9. **Cleanup** — Restores any remaining SSDT changes, frees allocated pages, and unloads the vulnerable driver service.

## Requirements

- Windows 10 1903+ (tested up to 24H2/25H2)
- Vulnerable driver with physical memory read/write support
- PDBs for the target Windows build
- Administrator privileges

## Building

Open `mapper.slnx` in Visual Studio 2022 and build x64 Release. Dependencies are included in `vendor/`.

## Usage

```cmd id="t9l4ex"
mapper.exe <path_to_driver.sys>
```

The driver must be a PE32+ image with relocations. Imports must resolve to loaded kernel modules.

## Supported OS builds

- 19041–19045: classic inline page-table decoding
- 22000–26100: `MiGetPageTablePfnBuddyRaw` or inline PID-safe decoding

The mapper detects the Windows build and picks the appropriate method.

## Architecture overview

```text id="7zqjhm"
entry.cpp                 Main flow
core/
  gate.hpp                SSDT hook and syscall handling
  phys.hpp                VA to PA translation
  krnl.hpp                Kernel modules and exports
  ntexp.hpp               PDB parsing and structure offsets
load/
  payload.hpp             PE parsing
  image.hpp               Mapping, relocations and physical writes
  import.hpp              Import resolution and page-table decoding
boot/
  bringup.hpp             Driver service setup
  device.hpp              Device communication and memory access
  residual/               Cleanup routines
```

## Notes

- `NtWriteVirtualMemory` is used as the SSDT hook target.
- Kernel memory access goes through the vulnerable driver's physical memory interface.
- The mapped image uses independent pages instead of pool allocations.
- Missing symbols or unresolved imports cause the mapper to abort.

## License

No license specified.
