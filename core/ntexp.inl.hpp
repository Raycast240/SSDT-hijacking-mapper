#pragma once

namespace nt {
	void memcpy( void* dst, void* src, std::uint64_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "memcpy" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel( fn_address, dst, src, size );
	}

	void memset( void* dst, int value, std::uint64_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "memset" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel( fn_address, dst, value, size );
	}

	void* mm_allocate_independent_pages( std::size_t size ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address )
			fn_address = g_pdb->get_symbol_address( oxorany( "MmAllocateIndependentPages" ) );

		if ( !fn_address ) {
			logging::print( oxorany( "Failed to resolve MmAllocateIndependentPages from PDB" ) );
			return nullptr;
		}

		return g_syscall->call_kernel<void*>( fn_address, size, 0xFFFFFFFFul );
	}

	physical_address_t mm_get_physical_address( void* virtual_address ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "MmGetPhysicalAddress" ) );
		}

		if ( !fn_address )
			return { };

		physical_address_t result{};
		result.m_quad_part = g_syscall->call_kernel<std::uint64_t>( fn_address, virtual_address );
		return result;
	}

	inline void ke_flush_entire_tb( bool invalidate, bool all_processors ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeFlushEntireTb" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, invalidate, all_processors );
	}

	inline void ke_invalidate_all_caches( ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeInvalidateAllCaches" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address );
	}

	inline void ke_flush_single_tb( std::uintptr_t address, bool all_processors, bool invalidate ) {
		static std::uint64_t fn_address = 0ull;
		if ( !fn_address ) {
			fn_address = g_pdb->get_symbol_address( oxorany( "KeFlushSingleTb" ) );
		}

		if ( !fn_address )
			return;

		g_syscall->call_kernel<void>( fn_address, address, all_processors, invalidate );
	}

	void flush_caches( void* address ) {
		ke_flush_entire_tb( true, true );
		ke_invalidate_all_caches( );
		ke_flush_single_tb( reinterpret_cast<std::uint64_t>( address ), true, true );
	}
}
