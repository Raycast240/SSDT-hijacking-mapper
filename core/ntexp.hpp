#pragma once

namespace nt {
	void memcpy( void* dst, void* src, std::uint64_t size );
	void* mm_allocate_independent_pages( std::size_t size );
	physical_address_t mm_get_physical_address( void* virtual_address );
	void ke_flush_entire_tb( bool invalidate, bool all_processors );
	void ke_invalidate_all_caches( );
	void ke_flush_single_tb( std::uintptr_t address, bool all_processors, bool invalidate );
	void flush_caches( void* address );
	void memset( void* dst, int value, std::uint64_t size );
}
