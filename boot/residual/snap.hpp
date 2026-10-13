#pragma once

namespace cleanup {

struct context_t {
    wchar_t service_name[ 32 ]{};
    wchar_t image_path_nt[ MAX_PATH ]{};
    wchar_t image_path_win32[ MAX_PATH ]{};
    std::uint32_t pe_time_date_stamp{ 0 };
    bool loaded{ false };
    bool device_open{ false };
    bool paging_ready{ false };
    bool syscall_ready{ false };
    bool teardown_started{ false };
};

inline context_t g_ctx{};

inline std::uint32_t pe_timestamp_from_bytes( const std::uint8_t* pe, std::size_t size ) {
    if ( !pe || size < 0x40 )
        return 0;
    if ( pe[ 0 ] != 'M' || pe[ 1 ] != 'Z' )
        return 0;
    const auto e_lfanew = *reinterpret_cast<const std::uint32_t*>( pe + 0x3C );
    if ( e_lfanew + 0x0C >= size )
        return 0;
    if ( pe[ e_lfanew ] != 'P' || pe[ e_lfanew + 1 ] != 'E' )
        return 0;

    return *reinterpret_cast<const std::uint32_t*>( pe + e_lfanew + 8 );
}

inline bool build_paths( const wchar_t* service_name, context_t& ctx ) {
    if ( !service_name || !service_name[ 0 ] )
        return false;

    wcsncpy_s( ctx.service_name, service_name, _TRUNCATE );

    wchar_t temp[ MAX_PATH ]{};
    if ( !GetTempPathW( MAX_PATH, temp ) )
        return false;

    _snwprintf_s( ctx.image_path_win32, _TRUNCATE, L"%s%s.log", temp, service_name );
    _snwprintf_s( ctx.image_path_nt, _TRUNCATE, L"\\??\\%s", ctx.image_path_win32 );
    ctx.pe_time_date_stamp = pe_timestamp_from_bytes( driver_bytes, sizeof( driver_bytes ) );
    if ( !ctx.pe_time_date_stamp ) {

        logging::print( oxorany( "cleanup: pe_time_date_stamp=0 from driver_bytes" ) );
        return false;
    }
    return true;
}

inline bool kernel_va_plausible( std::uint64_t va ) {

    return va >= 0xFFFF800000000000ULL;
}

inline bool is_paging_ready( ) {
    return g_ctx.device_open && g_ctx.paging_ready;
}

}
