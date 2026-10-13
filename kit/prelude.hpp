#pragma once
#include <chrono>
#include <ctime>
#include <vector>
#include <Windows.h>
#include <fstream>
#include <winternl.h>
#include <cstdint>
#include <dia2.h>
#include <diacreate.h>
#include <atlbase.h>
#include <string>
#include <memory>

#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "ntdll.lib")

#include <vendor/ia32.hpp>
#include <vendor/oxorany/include.h>

#include <common/log.hpp>
#include <common/util.hpp>

#include <kit/symbols.hpp>
auto g_pdb = std::make_shared<pdb::c_pdb>( oxorany( "ntoskrnl.exe" ) );

#include <boot/blob.hpp>
#include <boot/scm.hpp>

#include <boot/device.hpp>
auto g_driver = std::make_shared<driver::c_driver>( );

#include <core/krnl.hpp>
#include <core/ntexp.hpp>

#include <core/phys.hpp>
#include <core/tables.hpp>
auto g_paging = std::make_shared<paging::c_paging>( );

#include <core/gate.hpp>
auto g_syscall = std::make_shared<syscall::c_syscall>( );

#include <boot/residual/sweep.hpp>

#include <boot/bringup.hpp>
auto g_service = std::make_shared<service::c_service>( );

#include <load/pe.hpp>
#include <load/import.hpp>
#include <load/cave.hpp>
#include <load/payload.hpp>
#include <load/image.hpp>

#include <core/ntexp.inl.hpp>
#include <common/halt.hpp>
