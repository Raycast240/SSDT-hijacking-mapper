#pragma once

namespace paging {
    constexpr auto page_4kb_size = 0x1000ull;
    constexpr auto page_2mb_size = 0x200000ull;
    constexpr auto page_1gb_size = 0x40000000ull;

    constexpr auto page_shift = 12ull;

    constexpr auto page_4kb_mask = 0xFFFull;
    constexpr auto page_2mb_mask = 0x1FFFFFull;
    constexpr auto page_1gb_mask = 0x3FFFFFFFull;

    enum class e_pt_protection {
        none,
        read_write,
        read_write_execute
    };

    struct pt_entries_t {
        pml4e m_pml4e;
        pdpte m_pdpte;
        pde m_pde;
        pte m_pte;
    };

    class c_paging {
    public:
        c_paging( ) { }
        ~c_paging( ) { }

        std::uint64_t m_directory_table_base{ };

        bool setup( ) {
            const auto kpcr_self_off      = g_pdb->get_struct_member( oxorany( "_KPCR" ),              oxorany( "Self" ) );
            const auto kpcr_prcb_off      = g_pdb->get_struct_member( oxorany( "_KPCR" ),              oxorany( "Prcb" ) );
            const auto kpcr_idt_off       = g_pdb->get_struct_member( oxorany( "_KPCR" ),              oxorany( "IdtBase" ) );
            const auto prcb_pstate_off    = g_pdb->get_struct_member( oxorany( "_KPRCB" ),             oxorany( "ProcessorState" ) );
            const auto pstate_special_off = g_pdb->get_struct_member( oxorany( "_KPROCESSOR_STATE" ),  oxorany( "SpecialRegisters" ) );
            const auto special_cr3_off    = g_pdb->get_struct_member( oxorany( "_KSPECIAL_REGISTERS" ),oxorany( "Cr3" ) );
            const auto special_cr4_off    = g_pdb->get_struct_member( oxorany( "_KSPECIAL_REGISTERS" ),oxorany( "Cr4" ) );

            if ( !kpcr_prcb_off || !prcb_pstate_off || !special_cr3_off ) {
                logging::print( oxorany( "Failed to resolve KPCR offsets from PDB" ) );
                return false;
            }

            const auto cr3_offset_in_kpcr = kpcr_prcb_off + prcb_pstate_off + pstate_special_off + special_cr3_off;
            const auto cr4_offset_in_kpcr = kpcr_prcb_off + prcb_pstate_off + pstate_special_off + special_cr4_off;

            if ( cr3_offset_in_kpcr + sizeof( std::uint64_t ) > page_4kb_size ||
                 cr4_offset_in_kpcr + sizeof( std::uint64_t ) > page_4kb_size ) {
                logging::print( oxorany( "Aborted: KPCR CR3/CR4 offset exceeds 4 KB" ) );
                return false;
            }

            const auto page_buf = std::make_unique< std::uint8_t[ ] >( page_4kb_size );

            constexpr std::uint64_t scan_fast   = 0x8000'0000ULL;
            constexpr std::uint64_t scan_extend = 0x1'0000'0000ULL;
            auto try_scan = [ & ] ( std::uint64_t start, std::uint64_t end ) -> bool {
                for ( std::uint64_t pa = start; pa < end; pa += page_4kb_size ) {
                    if ( !g_driver->read_physical_memory( pa, page_buf.get( ), page_4kb_size ) )
                        continue;

                    const auto self_va = *reinterpret_cast<std::uint64_t*>( page_buf.get( ) + kpcr_self_off );
                    if ( ( self_va >> 48 ) != 0xFFFF )
                        continue;

                    if ( kpcr_idt_off && kpcr_idt_off + sizeof( std::uint64_t ) <= page_4kb_size ) {
                        const auto idt_va = *reinterpret_cast<std::uint64_t*>( page_buf.get( ) + kpcr_idt_off );
                        if ( ( idt_va >> 48 ) != 0xFFFF )
                            continue;
                    }

                    auto cr3 = *reinterpret_cast<std::uint64_t*>( page_buf.get( ) + cr3_offset_in_kpcr );
                    if ( !cr3 )
                        continue;
                    if ( cr3 >> 52 )
                        continue;
                    cr3 &= ~0xFFFULL;
                    if ( !cr3 )
                        continue;
                    if ( cr3 >= scan_extend )
                        continue;

                    std::uint64_t cr4 = 0;
                    if ( special_cr4_off ) {
                        cr4 = *reinterpret_cast<std::uint64_t*>( page_buf.get( ) + cr4_offset_in_kpcr );
                        if ( !cr4 )
                            continue;
                        if ( cr4 >> 32 )
                            continue;
                        if ( !( cr4 & ( 1ULL << 5 ) ) )
                            continue;
                    }

                    this->m_directory_table_base = cr3;
                    const auto translated_pa = this->translate_linear( self_va );
                    if ( !translated_pa || ( translated_pa & ~0xFFFULL ) != pa ) {
                        this->m_directory_table_base = 0;
                        continue;
                    }

                    if ( special_cr4_off && ( cr4 & ( 1ULL << 12 ) ) ) {
                        logging::print( oxorany( "Aborted: CR4.LA57 is set (5-level paging is not supported)" ) );
                        this->m_directory_table_base = 0;
                        return false;
                    }

                    logging::print( oxorany( "Found system CR3 0x%llx (KPCR physical 0x%llx)" ), cr3, pa );
                    return true;
                }
                return false;
            };

            if ( try_scan( 0, scan_fast ) )
                return true;

            logging::spin( oxorany( "Scanning physical memory (extended)" ) );
            if ( try_scan( scan_fast, scan_extend ) )
                return true;

            logging::print( oxorany( "Failed to locate KPCR within 4 GB of physical memory" ) );
            return false;
        }

        std::uint64_t translate_linear( std::uint64_t addr, std::uint32_t* page_size = 0 ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return false;

            if ( pt_entries.m_pdpte.hard.page_size ) {
                if ( page_size ) *page_size = page_1gb_size;
                return ( pt_entries.m_pdpte.hard.pfn << 12 ) + ( addr & page_1gb_mask );
            }

            if ( pt_entries.m_pde.hard.page_size ) {
                if ( page_size ) *page_size = page_2mb_size;
                return ( pt_entries.m_pde.hard.pfn << 12 ) + ( addr & page_2mb_mask );
            }

            if ( page_size ) *page_size = page_4kb_size;
            return ( pt_entries.m_pte.hard.pfn << 12 ) + ( addr & page_4kb_mask );
        }

        std::uint64_t get_pte_address( std::uint64_t addr ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, addr ) )
                return 0;

            if ( entries.m_pdpte.hard.page_size || entries.m_pde.hard.page_size )
                return 0;

            return ( entries.m_pde.hard.pfn << page_shift ) +
                ( virt_addr_t{ addr }.pte_index * sizeof( pte ) );
        }

        std::uint32_t get_page_size( std::uint64_t addr ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return false;

            if ( pt_entries.m_pdpte.hard.page_size )
                return page_1gb_size;

            if ( pt_entries.m_pde.hard.page_size )
                return page_2mb_size;
            return page_4kb_size;
        }

        bool is_mapped_executable( std::uint64_t addr ) {
            pt_entries_t e{};
            if ( !hyperspace_entries( e, addr ) )
                return false;
            if ( e.m_pml4e.hard.no_execute )
                return false;
            if ( e.m_pdpte.hard.no_execute )
                return false;
            if ( e.m_pdpte.hard.page_size )
                return true;
            if ( e.m_pde.hard.no_execute )
                return false;
            if ( e.m_pde.hard.page_size )
                return true;
            return e.m_pte.hard.present && !e.m_pte.hard.no_execute;
        }

        e_pt_protection get_page_protect( std::uint64_t addr ) {
            pt_entries_t pt_entries{};
            if ( !hyperspace_entries( pt_entries, addr ) )
                return e_pt_protection::none;

            if ( pt_entries.m_pdpte.hard.page_size ) {
                if ( !pt_entries.m_pdpte.hard.no_execute )
                    return e_pt_protection::read_write_execute;
                return pt_entries.m_pdpte.hard.read_write ? e_pt_protection::read_write : e_pt_protection::none;
            }

            if ( pt_entries.m_pde.hard.page_size ) {
                if ( !pt_entries.m_pde.hard.no_execute )
                    return e_pt_protection::read_write_execute;
                return pt_entries.m_pde.hard.read_write ? e_pt_protection::read_write : e_pt_protection::none;
            }

            if ( !pt_entries.m_pte.hard.no_execute )
                return e_pt_protection::read_write_execute;
            return pt_entries.m_pte.hard.read_write ? e_pt_protection::read_write : e_pt_protection::none;
        }

        bool set_pte_executable( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;
            if ( entries.m_pdpte.hard.page_size || entries.m_pde.hard.page_size )
                return false;
            if ( !entries.m_pte.hard.present )
                return false;

            entries.m_pte.hard.no_execute = 0;
            entries.m_pte.hard.present = 1;
            entries.m_pte.hard.read_write = 1;

            virt_addr_t va{ address };
            return write_pt_entry( entries.m_pde, va.pte_index, entries.m_pte );
        }

        bool make_range_executable( std::uint64_t address, std::size_t size ) {
            if ( !address || !size )
                return false;

            const auto end = address + size;
            for ( auto va = address & ~page_4kb_mask; va < end; va += page_4kb_size ) {
                auto page_size = get_page_size( va );
                if ( page_size == page_1gb_size ) {
                    if ( !split_1gb_to_4kb( va ) )
                        return false;
                    page_size = get_page_size( va );
                }
                else if ( page_size == page_2mb_size ) {
                    if ( !split_2mb_to_4kb( va ) )
                        return false;
                    page_size = get_page_size( va );
                }
                if ( page_size != page_4kb_size )
                    return false;
                if ( !set_pte_executable( va ) )
                    return false;
            }

            nt::flush_caches( reinterpret_cast<void*>( address ) );

            pt_entries_t first{};
            pt_entries_t last{};
            if ( !hyperspace_entries( first, address ) || !hyperspace_entries( last, end - 1 ) )
                return false;
            if ( first.m_pde.hard.page_size || last.m_pde.hard.page_size ||
                 first.m_pdpte.hard.page_size || last.m_pdpte.hard.page_size )
                return false;
            if ( first.m_pte.hard.no_execute || last.m_pte.hard.no_execute ) {
                logging::print( oxorany( "Aborted: cave PTE still NX after split (first=%u last=%u)" ),
                    first.m_pte.hard.no_execute, last.m_pte.hard.no_execute );
                return false;
            }
            return true;
        }

        bool split_2mb_to_4kb( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;

            if ( !entries.m_pde.hard.present || !entries.m_pde.hard.page_size )
                return false;

            auto new_pt_va = nt::mm_allocate_independent_pages( page_4kb_size );
            if ( !new_pt_va ) return false;
            nt::memset( new_pt_va, 0, page_4kb_size );

            const auto new_pt_pa = mmu::virtual_to_physical(
                reinterpret_cast<std::uint64_t>( new_pt_va ) );
            if ( !new_pt_pa ) return false;

            const auto base_pfn = entries.m_pde.hard.pfn;
            const auto inherit_nx = entries.m_pde.hard.no_execute;
            for ( auto idx = 0u; idx < 512u; ++idx ) {
                pte entry{};
                entry.hard.present = 1;
                entry.hard.read_write = entries.m_pde.hard.read_write;
                entry.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
                entry.hard.page_write_through = entries.m_pde.hard.page_write_through;
                entry.hard.cached_disable = entries.m_pde.hard.cached_disable;
                entry.hard.global = entries.m_pde.hard.global;
                entry.hard.no_execute = inherit_nx;
                entry.hard.pfn = base_pfn + idx;

                const auto pte_pa = new_pt_pa + ( idx * sizeof( pte ) );
                if ( !g_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                    return false;
            }

            pde new_pde{};
            new_pde.hard.present = 1;
            new_pde.hard.read_write = entries.m_pde.hard.read_write;
            new_pde.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
            new_pde.hard.page_write_through = entries.m_pde.hard.page_write_through;
            new_pde.hard.cached_disable = entries.m_pde.hard.cached_disable;
            new_pde.hard.page_size = 0;
            new_pde.hard.no_execute = 0;
            new_pde.hard.pfn = new_pt_pa >> page_shift;

            virt_addr_t va{ address };
            if ( !write_pt_entry( entries.m_pdpte, va.pde_index, new_pde ) )
                return false;

            nt::flush_caches( reinterpret_cast<void*>( address ) );
            return true;
        }

        bool split_1gb_to_4kb( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;

            if ( !entries.m_pdpte.hard.present || !entries.m_pdpte.hard.page_size )
                return false;

            auto new_pd_va = nt::mm_allocate_independent_pages( page_4kb_size );
            if ( !new_pd_va ) return false;

            const auto new_pd_pa = mmu::virtual_to_physical(
                reinterpret_cast<std::uint64_t>( new_pd_va ) );
            if ( !new_pd_pa ) return false;

            const auto base_pfn = entries.m_pdpte.hard.pfn;
            for ( auto pd_idx = 0u; pd_idx < 512u; ++pd_idx ) {
                auto new_pt_va = nt::mm_allocate_independent_pages( page_4kb_size );
                if ( !new_pt_va ) return false;

                const auto new_pt_pa = mmu::virtual_to_physical(
                    reinterpret_cast<std::uint64_t>( new_pt_va ) );
                if ( !new_pt_pa ) return false;

                const auto pd_base_pfn = base_pfn + ( pd_idx * 512u );
                const auto inherit_nx = entries.m_pdpte.hard.no_execute;
                for ( auto pt_idx = 0u; pt_idx < 512u; ++pt_idx ) {
                    pte entry{};
                    entry.hard.present = 1;
                    entry.hard.read_write = entries.m_pdpte.hard.read_write;
                    entry.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
                    entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                    entry.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
                    entry.hard.no_execute = inherit_nx;
                    entry.hard.pfn = pd_base_pfn + pt_idx;

                    const auto pte_pa = new_pt_pa + ( pt_idx * sizeof( pte ) );
                    if ( !g_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                        return false;
                }

                pde pd_entry{};
                pd_entry.hard.present = 1;
                pd_entry.hard.read_write = entries.m_pdpte.hard.read_write;
                pd_entry.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
                pd_entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                pd_entry.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
                pd_entry.hard.page_size = 0;
                pd_entry.hard.no_execute = 0;
                pd_entry.hard.pfn = new_pt_pa >> page_shift;

                const auto pde_pa = new_pd_pa + ( pd_idx * sizeof( pde ) );
                if ( !g_driver->write_physical_memory( pde_pa, &pd_entry, sizeof( pde ) ) )
                    return false;
            }

            pdpte new_pdpte{};
            new_pdpte.hard.present = 1;
            new_pdpte.hard.read_write = entries.m_pdpte.hard.read_write;
            new_pdpte.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
            new_pdpte.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
            new_pdpte.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
            new_pdpte.hard.page_size = 0;
            new_pdpte.hard.no_execute = 0;
            new_pdpte.hard.pfn = new_pd_pa >> page_shift;

            virt_addr_t va{ address };
            if ( !write_pt_entry( entries.m_pml4e, va.pdpte_index, new_pdpte ) )
                return false;

            nt::flush_caches( reinterpret_cast<void*>( address ) );
            return true;
        }

        bool read_virtual_memory( std::uint64_t addr, void* buf, std::size_t size ) {
            auto remaining = size;
            auto dst = reinterpret_cast<std::uint8_t*>( buf );
            auto current_va = addr;

            while ( remaining > 0 ) {
                auto pa = translate_linear( current_va );
                if ( !pa ) return false;

                const auto page_offset = current_va & 0xFFF;
                const auto chunk = min( remaining, 0x1000 - page_offset );

                if ( !g_driver->read_physical_memory( pa, dst, chunk ) )
                    return false;

                current_va += chunk;
                dst += chunk;
                remaining -= chunk;
            }

            return true;
        }

        bool write_virtual_memory( std::uint64_t addr, const void* buf, std::size_t size ) {
            auto remaining = size;
            auto src = reinterpret_cast<const std::uint8_t*>( buf );
            auto current_va = addr;

            while ( remaining > 0 ) {
                auto pa = translate_linear( current_va );
                if ( !pa ) return false;

                const auto page_offset = current_va & 0xFFF;
                const auto chunk = min( remaining, 0x1000 - page_offset );

                if ( !g_driver->write_physical_memory( pa, src, chunk ) )
                    return false;

                current_va += chunk;
                src += chunk;
                remaining -= chunk;
            }

            return true;
        }

        bool hyperspace_entries( pt_entries_t& entries, std::uint64_t address ) {
            virt_addr_t va{ address };

            if ( !g_driver->read_physical_memory(
                m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
                &entries.m_pml4e, sizeof( pml4e ) ) )
                return false;

            if ( !entries.m_pml4e.hard.present )
                return false;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pml4e.hard.pfn << 12 ) + ( sizeof( pdpte ) * va.pdpte_index ),
                &entries.m_pdpte, sizeof( pdpte ) ) )
                return false;

            if ( !entries.m_pdpte.hard.present )
                return false;

            if ( entries.m_pdpte.hard.page_size )
                return true;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pdpte.hard.pfn << 12 ) + ( sizeof( pde ) * va.pde_index ),
                &entries.m_pde, sizeof( pde ) ) )
                return false;

            if ( !entries.m_pde.hard.present )
                return false;

            if ( entries.m_pde.hard.page_size )
                return true;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
                &entries.m_pte, sizeof( pte ) ) )
                return false;

            if ( !entries.m_pte.hard.present )
                return false;

            return true;
        }

    private:
        template<typename parent_t, typename entry_t>
        bool write_pt_entry( const parent_t& parent, std::size_t index, const entry_t& entry ) {
            const auto pa = ( parent.hard.pfn << 12 ) + ( index * sizeof( entry_t ) );
            return g_driver->write_physical_memory( pa, &entry, sizeof( entry_t ) );
        }
    };
}
