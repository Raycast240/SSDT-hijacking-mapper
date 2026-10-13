#pragma once
#include <memory>
#include <algorithm>
#include <cstring>

namespace cleanup {
namespace pattern {

inline bool mask_match( const std::uint8_t* data, const std::uint8_t* pat, const char* mask, std::size_t len ) {
    for ( std::size_t i = 0; i < len; ++i ) {
        if ( mask[ i ] == 'x' && data[ i ] != pat[ i ] )
            return false;
    }
    return true;
}

inline std::uint64_t find_pattern( std::uint64_t base, std::size_t size,
    const std::uint8_t* pat, const char* mask ) {
    if ( !base || !size || !pat || !mask )
        return 0;
    const auto len = std::strlen( mask );
    if ( !len || size < len )
        return 0;

    constexpr std::size_t k_chunk = 0x10000;
    auto buf = std::make_unique< std::uint8_t[ ] >( k_chunk + len );

    for ( std::size_t off = 0; off + len <= size; ) {
        const auto this_size = ( std::min )( k_chunk + len, size - off );
        if ( !g_paging->read_virtual_memory( base + off, buf.get( ), this_size ) )
            return 0;

        const auto scan_end = this_size >= len ? this_size - len : 0;
        for ( std::size_t i = 0; i <= scan_end; ++i ) {
            if ( mask_match( buf.get( ) + i, pat, mask, len ) )
                return base + off + i;
        }

        if ( off + k_chunk >= size )
            break;
        off += k_chunk;
    }
    return 0;
}

inline std::uint64_t resolve_relative( std::uint64_t instr, std::uint32_t disp_off, std::uint32_t instr_len ) {
    std::int32_t rel = 0;
    if ( !g_paging->read_virtual_memory( instr + disp_off, &rel, sizeof( rel ) ) )
        return 0;
    return instr + instr_len + static_cast<std::int64_t>( rel );
}

inline bool find_section( std::uint64_t image_base, const char* name,
    std::uint64_t* out_va, std::uint32_t* out_size ) {
    IMAGE_DOS_HEADER dos{};
    if ( !g_paging->read_virtual_memory( image_base, &dos, sizeof( dos ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE )
        return false;

    IMAGE_NT_HEADERS64 nt{};
    if ( !g_paging->read_virtual_memory( image_base + dos.e_lfanew, &nt, sizeof( nt ) ) )
        return false;
    if ( nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.NumberOfSections == 0 ||
         nt.FileHeader.NumberOfSections > 96 )
        return false;

    const auto sec_va = image_base + dos.e_lfanew +
        offsetof( IMAGE_NT_HEADERS64, OptionalHeader ) +
        nt.FileHeader.SizeOfOptionalHeader;

    for ( std::uint16_t i = 0; i < nt.FileHeader.NumberOfSections; ++i ) {
        IMAGE_SECTION_HEADER sec{};
        if ( !g_paging->read_virtual_memory( sec_va + i * sizeof( sec ), &sec, sizeof( sec ) ) )
            return false;
        char sn[ 9 ]{};
        memcpy( sn, sec.Name, 8 );
        if ( !_stricmp( sn, name ) ) {
            *out_va = image_base + sec.VirtualAddress;
            *out_size = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            if ( *out_size > 0x400000 )
                *out_size = 0x400000;
            return *out_va && *out_size;
        }
    }
    return false;
}

}
}
