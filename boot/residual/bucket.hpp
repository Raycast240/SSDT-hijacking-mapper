#pragma once
#include "scan.hpp"
#include <algorithm>

namespace cleanup {
namespace hash_bucket {

#pragma pack(push, 8)
struct hash_bucket_entry_t {
    hash_bucket_entry_t* next;
    UNICODE_STRING       driver_name;

};
#pragma pack(pop)

inline std::uint32_t ci_image_size( std::uint64_t base ) {
    IMAGE_DOS_HEADER dos{};
    if ( !g_paging->read_virtual_memory( base, &dos, sizeof( dos ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE )
        return 0;
    IMAGE_NT_HEADERS64 nt{};
    if ( !g_paging->read_virtual_memory( base + dos.e_lfanew, &nt, sizeof( nt ) ) ||
         nt.Signature != IMAGE_NT_SIGNATURE )
        return 0;
    return nt.OptionalHeader.SizeOfImage;
}

inline bool resolve_list_and_lock( std::uint64_t ci_base,
    std::uint64_t* out_list_head_ptr, std::uint64_t* out_lock ) {
    const auto ci_size = ci_image_size( ci_base );
    if ( !ci_size || ci_size > 0x2000000 ) {
        logging::print( oxorany( "cleanup/hash: bad ci.dll SizeOfImage - skip" ) );
        return false;
    }

    std::uint64_t page_va = 0;
    std::uint32_t page_size = 0;
    if ( !pattern::find_section( ci_base, oxorany( "PAGE" ), &page_va, &page_size ) ) {
        logging::print( oxorany( "cleanup/hash: ci.dll PAGE section not found - skip" ) );
        return false;
    }

    const std::uint8_t list_pat[ ] = {
        0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00,
        0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00
    };
    const char* list_mask = "xxx????x?xxxxxxx";

    auto list_sig = pattern::find_pattern( page_va, page_size, list_pat, list_mask );
    if ( !list_sig ) {
        logging::print( oxorany( "cleanup/hash: g_KernelHashBucketList pattern miss - skip" ) );
        return false;
    }

    const auto list_ptr = pattern::resolve_relative( list_sig, 3, 7 );
    if ( !list_ptr || !kernel_va_plausible( list_ptr ) ) {
        logging::print( oxorany( "cleanup/hash: list head resolve bad - skip" ) );
        return false;
    }

    const std::uint64_t scan_base = list_sig > 50 ? list_sig - 50 : list_sig;
    const std::size_t scan_len = static_cast<std::size_t>( list_sig - scan_base + 8 );
    const std::uint8_t lock_pat[ ] = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00 };
    const char* lock_mask = "xxx????";

    auto lock_sig = pattern::find_pattern( scan_base, scan_len, lock_pat, lock_mask );
    if ( !lock_sig ) {

        if ( list_sig > page_va + 0x200 )
            lock_sig = pattern::find_pattern( list_sig - 0x200, 0x200, lock_pat, lock_mask );
    }
    if ( !lock_sig ) {
        logging::print( oxorany( "cleanup/hash: g_HashCacheLock pattern miss - skip" ) );
        return false;
    }

    const auto lock_va = pattern::resolve_relative( lock_sig, 3, 7 );
    if ( !lock_va || !kernel_va_plausible( lock_va ) ) {
        logging::print( oxorany( "cleanup/hash: lock resolve bad - skip" ) );
        return false;
    }

    if ( lock_va < ci_base || lock_va >= ci_base + ci_size ) {
        logging::print( oxorany( "cleanup/hash: lock VA outside ci.dll SizeOfImage - skip" ) );
        return false;
    }
    if ( list_ptr < ci_base || list_ptr >= ci_base + ci_size ) {
        logging::print( oxorany( "cleanup/hash: list VA outside ci.dll SizeOfImage - skip" ) );
        return false;
    }

    *out_list_head_ptr = list_ptr;
    *out_lock = lock_va;
    logging::print( oxorany( "cleanup/hash: list_head*=0x%llx lock=0x%llx size=0x%x" ),
        static_cast<unsigned long long>( list_ptr ),
        static_cast<unsigned long long>( lock_va ),
        ci_size );
    return true;
}

inline bool name_matches( const wchar_t* nm, const context_t& ctx ) {
    if ( !nm || !nm[ 0 ] )
        return false;

    auto ends_with_ci = [ ]( const wchar_t* hay, const wchar_t* needle ) -> bool {
        if ( !hay || !needle || !needle[ 0 ] )
            return false;
        const auto hl = wcslen( hay );
        const auto nl = wcslen( needle );
        if ( nl > hl )
            return false;
        return _wcsicmp( hay + ( hl - nl ), needle ) == 0;
    };

    if ( ctx.image_path_win32[ 0 ] && !_wcsicmp( nm, ctx.image_path_win32 ) )
        return true;
    if ( ctx.image_path_nt[ 0 ] && !_wcsicmp( nm, ctx.image_path_nt ) )
        return true;
    if ( ctx.image_path_nt[ 0 ] && wcsncmp( ctx.image_path_nt, L"\\??\\", 4 ) == 0 &&
         !_wcsicmp( nm, ctx.image_path_nt + 4 ) )
        return true;

    if ( ctx.service_name[ 0 ] ) {
        wchar_t want_log[ 80 ]{};
        _snwprintf_s( want_log, _TRUNCATE, L"%s.log", ctx.service_name );
        if ( !_wcsicmp( nm, want_log ) || !_wcsicmp( nm, ctx.service_name ) )
            return true;

        if ( ends_with_ci( nm, want_log ) ) {
            const auto hl = wcslen( nm );
            const auto nl = wcslen( want_log );
            if ( hl == nl || nm[ hl - nl - 1 ] == L'\\' || nm[ hl - nl - 1 ] == L'/' )
                return true;
        }
    }
    return false;
}

inline bool clear( const context_t& ctx ) {
    if ( !ctx.service_name[ 0 ] && !ctx.image_path_win32[ 0 ] )
        return false;
    if ( !g_syscall || !g_paging || !g_pdb )
        return false;

    auto mod = module::get_kernel_module( oxorany( "CI.dll" ) );
    if ( !mod )
        mod = module::get_kernel_module( oxorany( "ci.dll" ) );
    if ( !mod || !mod->m_module_base || !kernel_va_plausible( mod->m_module_base ) ) {
        logging::print( oxorany( "cleanup/hash: ci.dll not found - skip" ) );
        return true;
    }

    const auto ci_base = mod->m_module_base;

    std::uint64_t list_head_ptr = 0;
    std::uint64_t lock_va = 0;
    if ( !resolve_list_and_lock( ci_base, &list_head_ptr, &lock_va ) )
        return true;

    const auto acq = g_pdb->get_symbol_address( oxorany( "ExAcquireResourceExclusiveLite" ) );
    const auto rel = g_pdb->get_symbol_address( oxorany( "ExReleaseResourceLite" ) );
#if defined( CLEANUP_HASH_FREE_ENTRY ) && CLEANUP_HASH_FREE_ENTRY
    const auto free_tag = g_pdb->get_symbol_address( oxorany( "ExFreePoolWithTag" ) );
    const auto free_plain = g_pdb->get_symbol_address( oxorany( "ExFreePool" ) );
#endif

    if ( !acq || !rel ) {
        logging::print( oxorany( "cleanup/hash: lock exports missing - skip" ) );
        return true;
    }

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
        logging::print( oxorany( "cleanup/hash: lock busy - skip (no release, residual OK)" ) );
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

    bool cleaned = false;
    bool walk_ok = true;

    std::uint64_t prev_slot = list_head_ptr;
    std::uint64_t entry = 0;
    if ( !g_paging->read_virtual_memory( list_head_ptr, &entry, sizeof( entry ) ) ) {
        logging::print( oxorany( "cleanup/hash: cannot read list head - release" ) );
        walk_ok = false;
    }

    if ( walk_ok && !entry ) {
        logging::print( oxorany( "cleanup/hash: list empty (ok)" ) );
        cleaned = true;
    }

    int depth = 0;
    while ( walk_ok && entry && kernel_va_plausible( entry ) && depth++ < 256 ) {
        hash_bucket_entry_t ent{};
        if ( !g_paging->read_virtual_memory( entry, &ent, sizeof( ent ) ) ) {
            logging::print( oxorany( "cleanup/hash: entry read fail - stop walk" ) );
            break;
        }

        const auto name_len = ent.driver_name.Length;
        const auto name_buf = reinterpret_cast<std::uint64_t>( ent.driver_name.Buffer );
        const auto next = reinterpret_cast<std::uint64_t>( ent.next );

        if ( name_len && name_len < 1024 && name_buf && kernel_va_plausible( name_buf ) ) {
            wchar_t nm[ 520 ]{};
            const auto chars = ( std::min )( static_cast<std::size_t>( name_len / 2 ), std::size_t{ 510 } );
            if ( g_paging->read_virtual_memory( name_buf, nm, chars * sizeof( wchar_t ) ) ) {
                nm[ chars ] = 0;
                if ( name_matches( nm, ctx ) ) {
                    if ( !g_paging->write_virtual_memory( prev_slot, &next, sizeof( next ) ) ) {
                        logging::print( oxorany( "cleanup/hash: unlink write failed" ) );
                        break;
                    }

#if defined( CLEANUP_HASH_FREE_ENTRY ) && CLEANUP_HASH_FREE_ENTRY
                    if ( entry < ci_base || entry >= ci_base + 0x2000000ULL ) {
                        if ( free_plain )
                            g_syscall->call_kernel< void >( free_plain, reinterpret_cast<void*>( entry ) );
                        else if ( free_tag )
                            g_syscall->call_kernel< void >( free_tag, reinterpret_cast<void*>( entry ), 0ul );
                        else
                            logging::print( oxorany( "cleanup/hash: unlinked, free unresolved (leak ok)" ) );
                    } else {
                        logging::print( oxorany( "cleanup/hash: unlinked, refuse free of in-image ptr" ) );
                    }
#else
                    logging::print( oxorany( "cleanup/hash: unlinked %ls (no free - BSOD-safe)" ), nm );
#endif

                    logging::print( oxorany( "cleanup/hash: removed entry for %ls" ), nm );
                    cleaned = true;
                    break;
                }
            }
        }

        prev_slot = entry;
        entry = next;
        if ( entry == list_head_ptr )
            break;
    }

    if ( !cleaned && walk_ok )
        logging::print( oxorany( "cleanup/hash: no matching entry (ok)" ) );

    return true;
}

}
}
