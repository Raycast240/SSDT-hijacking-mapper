#pragma once

namespace map {
	class c_map {
	public:
		~c_map( ) { }
		c_map( std::shared_ptr< c_dependency > dependency ) : m_dependency( dependency ) { }

		bool create( ) {
			auto dependency_size = m_dependency->get_size( );
			m_mapped_image.resize( dependency_size );
			std::memset( m_mapped_image.data( ), 0, dependency_size );

			this->m_dependency_base = module::allocate_large_page( dependency_size );
			if ( !m_dependency_base )
				return false;

			if ( !g_syscall->in_ntos_range( m_dependency_base, dependency_size ) ) {
				logging::print( oxorany( "Aborted: cave 0x%llx size 0x%llx is outside ntoskrnl" ),
					m_dependency_base, static_cast<std::uint64_t>( dependency_size ) );
				return false;
			}

			if ( !g_syscall->refresh_after_paging( ) ) {
				logging::print( oxorany( "Aborted: SSDT invalid after cave allocation" ) );
				return false;
			}

			if ( !relocate( ) ) {
				logging::print( oxorany( "Failed to apply relocations" ) );
				return false;
			}

			if ( !map_delayed_imports( ) ) {
				logging::print( oxorany( "Failed to resolve delayed imports" ) );
				return false;
			}
			if ( !map_imports( ) ) {
				logging::print( oxorany( "Failed to resolve imports" ) );
				return false;
			}

			if ( !map_sections( ) ) {
				logging::print( oxorany( "Failed to map sections" ) );
				return false;
			}

			auto remaining = m_mapped_image.size( );
			auto src = m_mapped_image.data( );
			auto dst_va = m_dependency_base;

			while ( remaining > 0 ) {
				auto page_offset = dst_va & 0xFFF;
				auto chunk = min( remaining, ( std::size_t )( 0x1000 - page_offset ) );
				auto dst_pa = mmu::virtual_to_physical( dst_va );
				if ( !dst_pa ) {
					logging::print( oxorany( "Failed to translate VA 0x%llx" ), dst_va );
					return false;
				}
				if ( !g_driver->write_physical_memory( dst_pa, src, chunk ) ) {
					logging::print( oxorany( "Failed to write physical memory at 0x%llx" ), dst_pa );
					return false;
				}
				src += chunk;
				dst_va += chunk;
				remaining -= chunk;
			}

			logging::print( oxorany( "Image mapped successfully" ) );
			module::verify_signed_mapping(
				m_dependency_base,
				m_mapped_image.size( ),
				oxorany( "post-write" ),
				m_mapped_image.data( ) );
			return true;
		}

		bool execute( ) {
			this->m_entry_point = m_dependency->get_entry_point( );
			if ( !m_entry_point ) {
				logging::print( oxorany( "Failed to locate image entry point" ) );
				return false;
			}

			if ( !g_syscall->in_ntos( m_dependency_base + m_entry_point ) ) {
				logging::print( oxorany( "Aborted: entry point 0x%llx is outside ntoskrnl" ),
					m_dependency_base + m_entry_point );
				return false;
			}

			entry_t entry{ };
			entry.m_pdb.m_mm_allocate_independent_pages = g_pdb->get_symbol_address( oxorany( "MmAllocateIndependentPages" ) );
			entry.m_pdb.m_mm_free_independent_pages = g_pdb->get_symbol_address( oxorany( "MmFreeIndependentPages" ) );
			entry.m_pdb.m_mm_pfn_database = g_pdb->get_symbol_address( oxorany( "MmPfnDatabase" ) );

			entry.m_offsets.m_eprocess_active_process_links = g_pdb->get_struct_member( oxorany( "_EPROCESS" ), oxorany( "ActiveProcessLinks" ) );
			entry.m_offsets.m_kprocess_directory_table_base = g_pdb->get_struct_member( oxorany( "_KPROCESS" ), oxorany( "DirectoryTableBase" ) );
			entry.m_offsets.m_eprocess_unique_process_id    = g_pdb->get_struct_member( oxorany( "_EPROCESS" ), oxorany( "UniqueProcessId" ) );
			entry.m_offsets.m_eprocess_active_threads       = g_pdb->get_struct_member( oxorany( "_EPROCESS" ), oxorany( "ActiveThreads" ) );
			entry.m_offsets.m_mmpfn_size                    = g_pdb->get_struct_size( oxorany( "_MMPFN" ) );
			entry.m_offsets.m_mmpfn_pte_address             = g_pdb->get_struct_member( oxorany( "_MMPFN" ), oxorany( "PteAddress" ) );
			entry.m_offsets.m_eprocess_peb                  = g_pdb->get_struct_member( oxorany( "_EPROCESS" ), oxorany( "Peb" ) );

			const auto ntos_base = g_pdb->m_module_base;
			const auto os_build = buddy::os_build_number( );
			const auto pid_off = static_cast<std::uint32_t>(
				entry.m_offsets.m_eprocess_unique_process_id );
			const char* buddy_how = nullptr;
			entry.m_pdb.m_mi_get_page_table_pfn_buddy_raw =
				( os_build <= 19045u ) ? 0 : buddy::resolve_callable( ntos_base, &buddy_how, pid_off );

			const bool inline_ok = buddy::has_verified_inline_decode( pid_off );
			if ( !entry.m_pdb.m_mi_get_page_table_pfn_buddy_raw )
				buddy_how = "inline-pidsafe";

			logging::print( oxorany( "Resolved MmPfnDatabase at 0x%llx" ), entry.m_pdb.m_mm_pfn_database );
			logging::print( oxorany( "OS build %u" ), os_build );
			logging::print( oxorany( "Resolved buddy callable 0x%llx (%s, inline decode %s)" ),
				entry.m_pdb.m_mi_get_page_table_pfn_buddy_raw,
				buddy_how ? buddy_how : "none",
				inline_ok ? "yes" : "no" );
			logging::print( oxorany( "Resolved UniqueProcessId 0x%llx, ActiveThreads 0x%llx" ),
				entry.m_offsets.m_eprocess_unique_process_id, entry.m_offsets.m_eprocess_active_threads );
			if ( pid_off == 0x1d0u )
				logging::print( oxorany( "EPROCESS layout is 24H2/25H2 (UniqueProcessId 0x1d0)" ) );
			logging::print( oxorany( "Resolved _MMPFN size 0x%llx, PteAddress 0x%llx" ),
				entry.m_offsets.m_mmpfn_size, entry.m_offsets.m_mmpfn_pte_address );

			if ( !entry.m_pdb.m_mi_get_page_table_pfn_buddy_raw && !inline_ok ) {
				if ( os_build >= 18362u && os_build <= 19045u ) {
					logging::print( oxorany( "No buddy callable on build %u; using classic inline decode" ),
						os_build );
					buddy_how = "inline-classic";
				}
				else {
					logging::print( oxorany( "Aborted: no buddy callable and no verified page-table decode sequence" ) );
					return false;
				}
			}

			struct { const char* label; std::uint64_t value; } critical[ ] = {
				{ "MmAllocateIndependentPages",     entry.m_pdb.m_mm_allocate_independent_pages     },
				{ "MmPfnDatabase",                  entry.m_pdb.m_mm_pfn_database                   },
				{ "_KPROCESS.DirectoryTableBase",   entry.m_offsets.m_kprocess_directory_table_base },
				{ "_EPROCESS.UniqueProcessId",      entry.m_offsets.m_eprocess_unique_process_id    },
				{ "_EPROCESS.ActiveThreads",        entry.m_offsets.m_eprocess_active_threads       },
				{ "_MMPFN.size",                    entry.m_offsets.m_mmpfn_size                    },
				{ "_MMPFN.PteAddress",              entry.m_offsets.m_mmpfn_pte_address             },
			};

			for ( const auto& check : critical ) {
				if ( !check.value ) {
					logging::print( oxorany( "Aborted: required symbol '%s' failed to resolve" ), check.label );
					return false;
				}
			}

			entry.m_ntoskrnl_base = ntos_base;
			entry.m_image_size = m_mapped_image.size( );
			entry.m_image_base = m_dependency_base;

			if ( !entry.m_ntoskrnl_base || !entry.m_image_base || !entry.m_image_size ) {
				logging::print( oxorany( "Aborted: incomplete image or ntoskrnl handoff" ) );
				return false;
			}

			auto entry_address = reinterpret_cast<std::uint64_t>(
				nt::mm_allocate_independent_pages( sizeof( entry ) )
				);

			if ( !entry_address ) {
				logging::print( oxorany( "Failed to allocate entry context" ) );
				return false;
			}

			nt::memcpy(
				reinterpret_cast<void*>( entry_address ),
				&entry, sizeof( entry )
			);

			auto result = g_syscall->call_kernel< bool >(
				m_dependency_base + m_entry_point,
				entry_address );
			if ( !g_syscall->verify_restored( ) ) {
				logging::print( oxorany( "SSDT restore check failed after entry" ) );
				if ( !g_syscall->force_restore( ) ) {
					logging::print( oxorany( "SSDT leftover hijack remains after entry" ) );
					return false;
				}
			}
			if ( result ) {
				logging::print( oxorany( "Entry point returned success" ) );
				return true;
			}

			entry_t fail_entry{};
			if ( g_paging->read_virtual_memory(
				entry_address, &fail_entry, sizeof( fail_entry ) ) ) {
				const char* why = "unknown";
				switch ( fail_entry.m_status ) {
				case 1:  why = "null entry"; break;
				case 2:  why = "critical offsets"; break;
				case 3:  why = "Mm* symbols"; break;
				case 4:  why = "ntoskrnl base"; break;
				case 5:  why = "image base/size"; break;
				case 6:  why = "PsInitialSystemProcess"; break;
				case 7:  why = "system DTB"; break;
				case 8:  why = "physical ranges"; break;
				case 9:  why = "DPM init (PTE resolve)"; break;
				case 11: why = "WNF subscribe"; break;
				case 12: why = "system thread create"; break;
				case 13: why = "PFN CR3 init"; break;
				case 14: why = "hide driver pages"; break;
				default: break;
				}
				logging::print( oxorany( "Entry point failed (status=%llu: %s)" ),
					static_cast<unsigned long long>( fail_entry.m_status ), why );
			}
			else {
				logging::print( oxorany( "Entry point failed (could not read status)" ) );
			}
			return false;
		}

	private:
		std::shared_ptr< c_dependency > m_dependency;
		std::uint64_t m_dependency_base{ };
		std::uint64_t m_entry_point{ };
		std::vector< std::uint8_t > m_mapped_image;

		bool relocate( ) {
			auto delta_offset = m_dependency_base - m_dependency->get_image_base( );
			if ( m_dependency->is_reloc_stripped( ) ) {
				logging::print( oxorany( "Image has relocations stripped" ) );
				return false;
			}

			auto reloc_dir = m_dependency->get_reloc_directory( );
			if ( !reloc_dir ) {
				logging::print( oxorany( "Failed to locate relocation directory" ) );
				return false;
			}

			auto reloc_entry = m_dependency->rva_to_va<reloc_entry_t*>( reloc_dir->m_virtual_address );
			if ( !reloc_entry ) {
				logging::print( oxorany( "Failed to locate relocation entries" ) );
				return false;
			}

			auto reloc_end = reinterpret_cast<reloc_entry_t*>(
				reinterpret_cast<std::uint8_t*>( reloc_entry ) + reloc_dir->m_size
				);

			std::uint32_t reloc_blocks = 0;
			while ( reloc_entry < reloc_end && reloc_entry->m_size ) {
				auto record_count = ( reloc_entry->m_size - 8 ) >> 1;
				++reloc_blocks;

				for ( auto idx = 0u; idx < record_count; idx++ ) {
					auto offset = reloc_entry->m_item[ idx ].m_offset % 4096;
					auto type = reloc_entry->m_item[ idx ].m_type;
					if ( type == IMAGE_REL_BASED_ABSOLUTE )
						continue;

					auto reloc_addr = m_dependency->rva_to_va< std::uint8_t* >( reloc_entry->m_to_rva );
					auto reloc_va = reinterpret_cast<std::uint64_t*>( reloc_addr + offset );
					*reloc_va += delta_offset;
				}

				reloc_entry = reinterpret_cast<reloc_entry_t*>(
					reinterpret_cast<uint8_t*>( reloc_entry ) + reloc_entry->m_size
					);
			}

			logging::print( oxorany( "Applied %u relocation blocks" ), reloc_blocks );
			return true;
		}

		bool map_imports( ) {
			auto import_table = m_dependency->get_import_table( );
			if ( !import_table->m_virtual_address || !import_table->m_size ) {
				logging::print( oxorany( "Failed to locate import table" ) );
				return false;
			}

			auto import_desc = m_dependency->rva_to_va< import_descriptor_t* >( import_table->m_virtual_address );
			while ( import_desc->m_name ) {
				auto module_name = m_dependency->rva_to_va< LPSTR >( import_desc->m_name );
				if ( !module_name ) {
					logging::print( oxorany( "Failed to resolve import module name" ) );
					return false;
				}

				auto import_module = module::get_kernel_module( module_name );
				if ( !import_module || !import_module->m_module_base ) {
					logging::print( oxorany( "Failed to resolve module %s" ), module_name );
					return false;
				}

				auto first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( import_desc->m_first_thunk );
				auto orig_first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( import_desc->m_original_first_thunk );
				if ( !orig_first_thunk || !first_thunk ) {
					logging::print( oxorany( "Failed to resolve import thunk data" ) );
					return false;
				}

				while ( first_thunk->u1.address_of_data ) {
					if ( IMAGE_SNAP_BY_ORDINAL64( orig_first_thunk->u1.ordinal ) ) {
						auto ordinal = IMAGE_ORDINAL64( orig_first_thunk->u1.ordinal );
						first_thunk->u1.function = import_module->get_export( ( const char* )ordinal );
						if ( !first_thunk->u1.function ) {
							logging::print( oxorany( "Failed to resolve %s:%s" ), ( const char* )ordinal, module_name );
							return false;
						}
					}
					else {
						auto ibn = m_dependency->rva_to_va< nt_image_import_name_t* >( orig_first_thunk->u1.address_of_data );
						if ( !ibn ) {
							logging::print( oxorany( "Failed to read import by name" ) );
							return false;
						}

						first_thunk->u1.function = import_module->get_export( ibn->name );
						if ( !first_thunk->u1.function ) {
							logging::print( oxorany( "Failed to resolve %s:%s" ), ibn->name, module_name );
							return false;
						}
					}

					orig_first_thunk++;
					first_thunk++;
				}

				memset( module_name, 0, std::strlen( module_name ) );
				import_desc++;
			}

			return true;
		}

		bool map_delayed_imports( ) {
			auto delay_descriptor = m_dependency->get_delay_import_descriptor( );
			if ( !delay_descriptor->m_virtual_address || !delay_descriptor->m_size ) {
				return true;
			}

			auto delay_desc = m_dependency->rva_to_va< image_delayload_descriptor_t* >( delay_descriptor->m_virtual_address );
			while ( delay_desc->m_dll_name_rva ) {
				auto module_name = m_dependency->rva_to_va< LPSTR >( delay_desc->m_dll_name_rva );
				if ( !module_name ) {
					logging::print( oxorany( "Failed to resolve delayed import name" ) );
					return false;
				}

				auto import_module = module::get_kernel_module( module_name );
				if ( !import_module || !import_module->m_module_base ) {
					logging::print( oxorany( "Failed to resolve delayed import module %s" ), module_name );
					return false;
				}

				auto first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( delay_desc->m_import_address_table_rva );
				auto orig_first_thunk = m_dependency->rva_to_va< nt_image_thunk_data_t* >( delay_desc->m_import_name_table_rva );
				if ( !orig_first_thunk || !first_thunk ) {
					logging::print( oxorany( "Failed to resolve delayed import thunk data" ) );
					return false;
				}

				while ( first_thunk->u1.address_of_data ) {
					if ( IMAGE_SNAP_BY_ORDINAL64( orig_first_thunk->u1.ordinal ) ) {
						auto ordinal = IMAGE_ORDINAL64( orig_first_thunk->u1.ordinal );
						first_thunk->u1.function = import_module->get_export( ( const char* )ordinal );
					}
					else {
						auto ibn = m_dependency->rva_to_va< nt_image_import_name_t* >( orig_first_thunk->u1.address_of_data );
						if ( !ibn ) {
							logging::print( oxorany( "Failed to read delayed import by name" ) );
							return false;
						}

						first_thunk->u1.function = import_module->get_export( ibn->name );
					}

					if ( !first_thunk->u1.function ) {
						logging::print( oxorany( "Failed to resolve delayed import function" ) );
						return false;
					}

					orig_first_thunk++;
					first_thunk++;
				}

				delay_desc++;
			}

			return true;
		}

		bool map_sections( ) {
			auto section_count = m_dependency->get_section_count( );
			std::uint32_t copied = 0;
			for ( auto idx = 0ul; idx < section_count; idx++ ) {
				auto section = m_dependency->get_section( idx );
				if ( !section->m_virtual_address || !section->m_size_of_raw_data )
					continue;

				const auto& raw = m_dependency->get_raw_image( );
				if ( section->m_pointer_to_raw_data + section->m_size_of_raw_data > raw.size( ) )
					return false;
				if ( section->m_virtual_address + section->m_size_of_raw_data > m_mapped_image.size( ) )
					return false;

				auto section_buffer = m_mapped_image.data( ) + section->m_virtual_address;
				auto source_data = raw.data( ) + section->m_pointer_to_raw_data;
				std::memcpy( section_buffer, source_data, section->m_size_of_raw_data );
				++copied;
			}

			logging::print( oxorany( "Copied %u image sections" ), copied );
			return true;
		}
	};
}
