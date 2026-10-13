#pragma once

namespace cleanup {
namespace piddb {

#pragma pack(push, 8)
struct piddb_cache_entry_t {
    LIST_ENTRY     list;
    UNICODE_STRING driver_name;
    ULONG          time_date_stamp;
    NTSTATUS       load_status;
    char           pad[ 16 ];
};
#pragma pack(pop)

inline bool clear( const context_t& ctx ) {
    if ( !ctx.service_name[ 0 ] ) {
        logging::print( oxorany( "cleanup/piddb: no service name - skip" ) );
        return true;
    }
    if ( !ctx.pe_time_date_stamp ) {
        logging::print( oxorany( "cleanup/piddb: pe_time_date_stamp=0 - skip" ) );
        return true;
    }
    if ( !g_syscall || !g_paging || !g_pdb )
        return true;

    const auto lock_va = g_pdb->get_symbol_address( oxorany( "PiDDBLock" ) );
    const auto table_va = g_pdb->get_symbol_address( oxorany( "PiDDBCacheTable" ) );
    const auto acq = g_pdb->get_symbol_address( oxorany( "ExAcquireResourceExclusiveLite" ) );
    const auto rel = g_pdb->get_symbol_address( oxorany( "ExReleaseResourceLite" ) );
    const auto lookup = g_pdb->get_symbol_address( oxorany( "RtlLookupElementGenericTableAvl" ) );
    const auto del = g_pdb->get_symbol_address( oxorany( "RtlDeleteElementGenericTableAvl" ) );

    if ( !lock_va || !table_va || !acq || !rel || !lookup || !del ) {
        logging::print( oxorany( "cleanup/piddb: symbols incomplete - skip" ) );
        return true;
    }
    if ( !kernel_va_plausible( lock_va ) || !kernel_va_plausible( table_va ) ) {
        logging::print( oxorany( "cleanup/piddb: bad symbol VA - skip" ) );
        return true;
    }

    auto count_off = g_pdb->get_struct_member( oxorany( "_RTL_AVL_TABLE" ), oxorany( "NumberGenericTableElements" ) );
    if ( !count_off )
        count_off = 0x2C;
    std::uint32_t element_count = 0;
    if ( !g_paging->read_virtual_memory( table_va + count_off, &element_count, sizeof( element_count ) ) ) {
        logging::print( oxorany( "cleanup/piddb: cannot read table - skip" ) );
        return true;
    }
    if ( element_count > 0x10000 ) {
        logging::print( oxorany( "cleanup/piddb: absurd element count %u - skip" ), element_count );
        return true;
    }

    wchar_t name_log[ 64 ]{};
    _snwprintf_s( name_log, _TRUNCATE, L"%s.log", ctx.service_name );
    wchar_t name_bare[ 64 ]{};
    wcsncpy_s( name_bare, ctx.service_name, _TRUNCATE );

    unsigned char acquired = 0;
    for ( int i = 0; i < 40 && !acquired; ++i ) {
        acquired = g_syscall->call_kernel< unsigned char >(
            acq,
            reinterpret_cast<void*>( lock_va ),
            static_cast<unsigned char>( 0 )
        );
        if ( !acquired )
            Sleep( 10 );
    }
    if ( !acquired ) {
        logging::print( oxorany( "cleanup/piddb: lock busy - skip (no release)" ) );
        return true;
    }

    struct release_guard_t {
        std::uint64_t lock_va;
        std::uint64_t rel_fn;
        ~release_guard_t( ) {
            if ( lock_va && rel_fn && g_syscall )
                g_syscall->call_kernel< void >( rel_fn, reinterpret_cast<void*>( lock_va ) );
        }
    } release_guard{ lock_va, rel };

    auto try_lookup = [ & ]( wchar_t* nm ) -> std::uint64_t {
        UNICODE_STRING u{};
        u.Buffer = nm;
        u.Length = static_cast<USHORT>( wcslen( nm ) * sizeof( wchar_t ) );
        u.MaximumLength = u.Length + sizeof( wchar_t );
        piddb_cache_entry_t key{};
        key.driver_name = u;
        key.time_date_stamp = ctx.pe_time_date_stamp;

        return g_syscall->call_kernel< std::uint64_t >(
            lookup,
            reinterpret_cast<void*>( table_va ),
            &key
        );
    };

    auto found = try_lookup( name_log );
    if ( !found )
        found = try_lookup( name_bare );

    if ( found && kernel_va_plausible( found ) ) {

        LIST_ENTRY le{};
        bool list_ok = false;
        bool list_read_ok = g_paging->read_virtual_memory( found, &le, sizeof( le ) );
        if ( list_read_ok &&
             le.Flink && le.Blink &&
             kernel_va_plausible( reinterpret_cast<std::uint64_t>( le.Flink ) ) &&
             kernel_va_plausible( reinterpret_cast<std::uint64_t>( le.Blink ) ) ) {
            const auto flink = reinterpret_cast<std::uint64_t>( le.Flink );
            const auto blink = reinterpret_cast<std::uint64_t>( le.Blink );
            if ( g_paging->write_virtual_memory( blink, &le.Flink, sizeof( void* ) ) ) {
                if ( g_paging->write_virtual_memory( flink + sizeof( void* ), &le.Blink, sizeof( void* ) ) ) {
                    list_ok = true;
                } else {
                    const auto self = reinterpret_cast<void*>( found );
                    g_paging->write_virtual_memory( blink, &self, sizeof( void* ) );
                    logging::print( oxorany( "cleanup/piddb: half-unlink reversed - skip AVL delete" ) );
                }
            }
        }

        bool avl_deleted = false;
        if ( list_ok || ( list_read_ok && !le.Flink && !le.Blink ) ) {
            const auto ok = g_syscall->call_kernel< unsigned char >(
                del,
                reinterpret_cast<void*>( table_va ),
                reinterpret_cast<void*>( found )
            );
            avl_deleted = ( ok != 0 );
            if ( !avl_deleted )
                logging::print( oxorany( "cleanup/piddb: RtlDelete returned 0 - residual possible" ) );
        } else if ( !list_read_ok ) {
            logging::print( oxorany( "cleanup/piddb: list read failed - skip AVL delete (BSOD-safe)" ) );
        } else if ( !list_ok ) {
            logging::print( oxorany( "cleanup/piddb: list unlink failed - skip AVL delete (BSOD-safe)" ) );
        }

        if ( avl_deleted ) {
            const auto delete_count_off = g_pdb->get_struct_member( oxorany( "_RTL_AVL_TABLE" ), oxorany( "DeleteCount" ) );
            if ( delete_count_off ) {
                std::uint32_t delete_count = 0;
                if ( g_paging->read_virtual_memory( table_va + delete_count_off, &delete_count, sizeof( delete_count ) ) &&
                     delete_count > 0 && delete_count < 0x10000 ) {
                    delete_count--;
                    g_paging->write_virtual_memory( table_va + delete_count_off, &delete_count, sizeof( delete_count ) );
                }
            }
            logging::print( oxorany( "cleanup/piddb: removed entry stamp=0x%x" ), ctx.pe_time_date_stamp );
        }
    } else {
        logging::print( oxorany( "cleanup/piddb: entry not found (ok)" ) );
    }

    return true;
}

}
}
