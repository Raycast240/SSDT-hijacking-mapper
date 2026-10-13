#pragma once
#include <memory>

namespace cleanup {
namespace usermode {

inline void schedule_reboot_delete( const wchar_t* win32_path ) {
    if ( !win32_path || !win32_path[ 0 ] )
        return;

    MoveFileExW( win32_path, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT );
}

inline void wipe_image_file( const wchar_t* win32_path ) {
    if ( !win32_path || !win32_path[ 0 ] )
        return;

    HANDLE f = CreateFileW(
        win32_path,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if ( f == INVALID_HANDLE_VALUE )
        return;

    LARGE_INTEGER size{};
    if ( !GetFileSizeEx( f, &size ) || size.QuadPart <= 0 || size.QuadPart > 0x2000000 ) {
        CloseHandle( f );
        return;
    }

    const auto wipe_len = static_cast<DWORD>(
        size.QuadPart > 0x400000 ? 0x400000 : size.QuadPart );
    auto buf = std::make_unique< std::uint8_t[ ] >( 0x1000 );
    DWORD left = wipe_len;
    SetFilePointer( f, 0, nullptr, FILE_BEGIN );
    while ( left ) {
        const auto chunk = left > 0x1000 ? 0x1000u : left;
        for ( DWORD i = 0; i < chunk; ++i )
            buf[ i ] = static_cast<std::uint8_t>( ( GetTickCount( ) + i * 17u ) & 0xFF );
        DWORD written = 0;
        if ( !WriteFile( f, buf.get( ), chunk, &written, nullptr ) || !written )
            break;
        left -= written;
    }
    FlushFileBuffers( f );
    CloseHandle( f );
}

inline bool delete_image_file( const wchar_t* win32_path ) {
    if ( !win32_path || !win32_path[ 0 ] )
        return true;

    wipe_image_file( win32_path );

    for ( int i = 0; i < 8; ++i ) {
        if ( DeleteFileW( win32_path ) )
            return true;
        const auto err = GetLastError( );
        if ( err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND )
            return true;
        Sleep( 100 );
    }

    logging::print( oxorany( "Failed to delete image file; scheduled removal on reboot" ) );
    schedule_reboot_delete( win32_path );
    return false;
}

inline bool delete_service_key( const wchar_t* service_name ) {
    if ( !service_name || !service_name[ 0 ] )
        return false;

    HKEY services_key = nullptr;
    auto result = RegOpenKeyA(
        HKEY_LOCAL_MACHINE,
        oxorany( "SYSTEM\\CurrentControlSet\\Services" ),
        &services_key
    );
    if ( result != ERROR_SUCCESS )
        return false;

    result = RegDeleteKeyW( services_key, service_name );
    RegCloseKey( services_key );

    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND;
}

inline NTSTATUS nt_unload( const wchar_t* service_name ) {
    using nt_unload_driver_t = NTSTATUS( __stdcall* )( PUNICODE_STRING );
    auto* fn = reinterpret_cast<nt_unload_driver_t>(
        GetProcAddress( GetModuleHandleA( oxorany( "ntdll.dll" ) ), oxorany( "NtUnloadDriver" ) )
    );
    if ( !fn )
        return static_cast<NTSTATUS>( 0xC0000002L );

    auto path = service::build_driver_path( service_name );
    if ( !path.Buffer )
        return static_cast<NTSTATUS>( 0xC000000D );

    return fn( &path );
}

inline void teardown_after_close( context_t& ctx ) {
    if ( ctx.service_name[ 0 ] ) {
        const auto st = nt_unload( ctx.service_name );

        if ( st == 0 ||
             st == static_cast<NTSTATUS>( 0xC0000034L ) ||
             st == static_cast<NTSTATUS>( 0xC000003AL ) ) {
            logging::print( oxorany( "cleanup: U2 NtUnloadDriver OK (0x%x)" ), st );
        } else {
            logging::print( oxorany( "cleanup: U2 NtUnloadDriver status=0x%x" ), st );
        }
        ctx.loaded = false;
    }

    if ( ctx.image_path_win32[ 0 ] ) {
        if ( delete_image_file( ctx.image_path_win32 ) )
            logging::print( oxorany( "cleanup: U3 wipe+DeleteFile OK" ) );
        else
            logging::print( oxorany( "cleanup: U3 DeleteFile pending reboot" ) );
        ctx.image_path_win32[ 0 ] = 0;
        ctx.image_path_nt[ 0 ] = 0;
    }

    if ( ctx.service_name[ 0 ] ) {
        if ( delete_service_key( ctx.service_name ) )
            logging::print( oxorany( "cleanup: U4 RegDelete OK" ) );
        else
            logging::print( oxorany( "cleanup: U4 RegDelete failed" ) );
    }

    service::uninstall_orphan_log_services( ctx.service_name );
}

}
}
