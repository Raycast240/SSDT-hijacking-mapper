#pragma once

namespace module {
    class c_page_candidate {
    public:
        c_page_candidate( ) { }
        ~c_page_candidate( ) { }

        std::uint64_t m_base_address;
        std::uint32_t m_unused_space;
        bool          m_1gb_page;
        bool          m_2mb_page;
        bool          m_executable;
    };

    std::uint64_t find_unused_space( std::uint64_t section_base, std::uint32_t section_size, std::size_t space_size ) {
        if ( section_size < space_size )
            return 0;

        auto section_data = std::make_unique<std::uint8_t [ ]>( section_size );
        nt::memcpy( section_data.get( ),
            reinterpret_cast<void*>( section_base ),
            section_size );

        for ( auto idx = 0u; idx <= section_size - space_size; ) {
            bool found_space = true;
            for ( auto j = 0u; j < space_size; ++j ) {
                if ( section_data[ idx + j ] != 0x00 ) {
                    found_space = false;
                    idx += j + 1;
                    break;
                }
            }

            if ( found_space )
                return section_base + idx;
        }

        return 0;
    }

    inline const char* page_size_name( std::uint32_t page_size ) {
        if ( page_size == paging::page_1gb_size )
            return "1GB";
        if ( page_size == paging::page_2mb_size )
            return "2MB";
        if ( page_size == paging::page_4kb_size )
            return "4KB";
        return "unknown";
    }

    inline void verify_signed_mapping( std::uint64_t va, std::size_t image_size, const char* phase,
        const std::uint8_t* written = nullptr ) {
        const auto ntos = g_pdb->m_module_base;
        if ( !va || !ntos ) {
            logging::print( oxorany( "Signed-memory check [%s]: missing VA or ntoskrnl base" ), phase );
            return;
        }

        dos_header_t dos{};
        nt::memcpy( &dos, reinterpret_cast<void*>( ntos ), sizeof( dos ) );
        nt_headers_t nt{};
        nt::memcpy( &nt, reinterpret_cast<void*>( ntos + dos.m_lfanew ), sizeof( nt ) );

        const auto ntos_size = static_cast<std::uint64_t>( nt.m_size_of_image );
        const auto ntos_end = ntos + ntos_size;
        const auto alloc_end = va + image_size;
        const bool in_range = ( va >= ntos ) && ( alloc_end <= ntos_end ) && image_size != 0;

        char section_name[ 9 ]{};
        std::uint32_t section_chars = 0;
        auto section_headers_va = ( ntos + dos.m_lfanew ) + nt.m_size_of_optional_header + 0x18;
        for ( auto idx = 0; idx < nt.m_number_of_sections; idx++ ) {
            section_header_t section{};
            nt::memcpy( &section,
                reinterpret_cast<void*>( section_headers_va + ( idx * sizeof( section_header_t ) ) ),
                sizeof( section ) );
            const auto sec_base = ntos + section.m_virtual_address;
            const auto sec_end = sec_base + static_cast<std::uint64_t>( section.m_virtual_size );
            if ( va >= sec_base && va < sec_end ) {
                std::memcpy( section_name, section.m_name, 8 );
                section_chars = static_cast<std::uint32_t>( section.m_characteristics );
                break;
            }
        }

        const auto page_size = g_paging->get_page_size( va );
        const auto pfn = g_paging->translate_linear( va ) >> 12;
        const bool exec_flag = ( section_chars & 0x20000000u ) != 0;

        if ( in_range && !exec_flag )
            logging::money( oxorany( "SIGNED MEMORY  PASS  [%s]" ), phase );
        else
            logging::print( oxorany( "SIGNED MEMORY  FAIL  [%s]" ), phase );

        logging::money( oxorany( "  backed by ntoskrnl.exe  (Microsoft-signed module)" ) );
        logging::print( oxorany( "  ntoskrnl     0x%llx - 0x%llx" ), ntos, ntos_end );
        logging::print( oxorany( "  your driver  0x%llx - 0x%llx" ), va, alloc_end );
        logging::money( oxorany( "  inside signed range: %s" ), in_range ? "YES" : "NO" );
        logging::print( oxorany( "  section      %s  (%s)" ),
            section_name[ 0 ] ? section_name : "?",
            exec_flag ? "executable - unexpected" : "padding, not .text" );
        logging::print( oxorany( "  page         %s   pfn 0x%llx" ),
            page_size_name( page_size ), pfn );

        std::size_t probe = 0;
        if ( written && image_size ) {
            while ( probe < image_size && written[ probe ] == 0 )
                ++probe;
            if ( probe >= image_size )
                probe = 0;
        }

        std::uint8_t sample[ 4 ]{};
        const auto probe_va = va + probe;
        if ( !g_paging->read_virtual_memory( probe_va, sample, sizeof( sample ) ) ) {
            logging::print( oxorany( "  payload      unreadable at +0x%llx" ),
                static_cast<std::uint64_t>( probe ) );
        } else if ( !written ) {
            const bool hole = sample[ 0 ] == 0 && sample[ 1 ] == 0 && sample[ 2 ] == 0 && sample[ 3 ] == 0;
            if ( hole )
                logging::print( oxorany( "  payload      unused hole (zeros) - ready to write" ) );
            else
                logging::print( oxorany( "  payload      already occupied %02x %02x %02x %02x" ),
                    sample[ 0 ], sample[ 1 ], sample[ 2 ], sample[ 3 ] );
        } else {
            const bool match = std::memcmp( sample, written + probe, sizeof( sample ) ) == 0;
            const bool hole = sample[ 0 ] == 0 && sample[ 1 ] == 0 && sample[ 2 ] == 0 && sample[ 3 ] == 0;
            if ( match && !hole )
                logging::money( oxorany( "  payload      written into ntoskrnl-backed pages (+0x%llx)" ),
                    static_cast<std::uint64_t>( probe ) );
            else if ( hole )
                logging::print( oxorany( "  payload      still zeros at +0x%llx - write did not land" ),
                    static_cast<std::uint64_t>( probe ) );
            else
                logging::print( oxorany( "  payload      mismatch at +0x%llx (%02x %02x %02x %02x)" ),
                    static_cast<std::uint64_t>( probe ),
                    sample[ 0 ], sample[ 1 ], sample[ 2 ], sample[ 3 ] );
        }
    }

    std::uint64_t allocate_large_page( std::size_t size ) {
        std::vector < c_page_candidate > page_candidates;
        const auto module_base = g_pdb->m_module_base;

        dos_header_t dos_header;
        nt::memcpy( &dos_header,
            reinterpret_cast<void*>( module_base ),
            sizeof( dos_header ) );
        if ( dos_header.m_magic != pe_magic_t::dos_header ) {
            logging::print( oxorany( "Invalid DOS header at 0x%llx" ), module_base );
            return 0;
        }

        nt_headers_t nt_headers;
        nt::memcpy( &nt_headers,
            reinterpret_cast<void*>( module_base + dos_header.m_lfanew ),
            sizeof( nt_headers ) );
        if ( nt_headers.m_signature != pe_magic_t::nt_headers
            || nt_headers.m_magic != pe_magic_t::opt_header ) {
            logging::print( oxorany( "Invalid PE header at 0x%llx" ), module_base );
            return 0;
        }

        auto section_headers_va = ( module_base + dos_header.m_lfanew )
            + nt_headers.m_size_of_optional_header + 0x18;
        for ( auto idx = 0; idx < nt_headers.m_number_of_sections; idx++ ) {
            section_header_t section_header;
            nt::memcpy( &section_header,
                reinterpret_cast<void*>( section_headers_va + ( idx * sizeof( section_header_t ) ) ),
                sizeof( section_header ) );
            if ( section_header.m_characteristics & 0x20000000 )
                continue;

            auto section_base = module_base + section_header.m_virtual_address;
            auto section_size = section_header.m_virtual_size;
            const auto ntos_end = module_base + static_cast<std::uint64_t>( nt_headers.m_size_of_image );
            if ( section_base >= ntos_end )
                continue;
            if ( section_base + section_size > ntos_end )
                section_size = static_cast<std::uint32_t>( ntos_end - section_base );

            std::vector <std::uint8_t> section_data;
            section_data.resize( section_size );
            nt::memcpy( section_data.data( ),
                reinterpret_cast<void*>( section_base ),
                section_size );

            auto target_address = find_unused_space( section_base, section_size, size );
            if ( target_address && target_address + size <= ntos_end ) {
                const auto page_size = g_paging->get_page_size( target_address );
                const auto page_protect = g_paging->get_page_protect( target_address );
                const auto zero_count = std::count( section_data.begin( ), section_data.end( ), 0x00 );

                c_page_candidate page_candidate;
                page_candidate.m_base_address = target_address;
                page_candidate.m_unused_space = static_cast<std::uint32_t>( zero_count );
                page_candidate.m_1gb_page = page_size == paging::page_1gb_size;
                page_candidate.m_2mb_page = page_size == paging::page_2mb_size;
                page_candidate.m_executable = page_protect == paging::e_pt_protection::read_write_execute;

                page_candidates.emplace_back( page_candidate );
            }
        }

        for ( auto& candidate : page_candidates ) {
            const auto target_address = candidate.m_base_address;
            if ( !candidate.m_executable )
                logging::print( oxorany( "Candidate page is not executable" ) );

            if ( !g_paging->make_range_executable( target_address, size ) ) {
                logging::print( oxorany( "Failed to make cave executable at 0x%llx; trying next candidate" ), target_address );
                continue;
            }

            if ( !g_syscall->refresh_after_paging( ) ) {
                logging::print( oxorany( "Aborted: SSDT invalid after page split at 0x%llx" ), target_address );
                return 0;
            }

            auto pte_address = g_paging->get_pte_address( target_address );
            if ( !pte_address )
                continue;

            if ( !g_paging->translate_linear( target_address ) )
                continue;

            logging::print( oxorany( "Allocated at 0x%llx (unused 0x%x)" ), target_address, candidate.m_unused_space );
            verify_signed_mapping( target_address, size, oxorany( "pre-write" ) );
            return target_address;
        }

        logging::print( oxorany( "No suitable space found in %d sections" ), nt_headers.m_number_of_sections );
        logging::print( oxorany( "Restart the system if an image was already mapped this boot" ) );
        return 0;
    }
}
