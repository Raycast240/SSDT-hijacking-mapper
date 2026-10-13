#pragma once

namespace module {
	class c_module {
	public:
		std::uint64_t m_module_base{ };

		explicit c_module( std::uint64_t module_base ) : m_module_base( module_base ) { }

		std::uintptr_t get_export( const char* export_name ) const {
			return g_pdb->get_symbol_address( export_name );
		}
	};

	std::unique_ptr< c_module > get_kernel_module( const char* module_name ) {
		unsigned long buffer_size = 0;
		auto status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>( 11 ),
			nullptr,
			0,
			&buffer_size
		);

		if ( status != 0xC0000004L )
			return nullptr;

		auto buffer = std::make_unique< std::uint8_t[ ] >( buffer_size );
		status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>( 11 ),
			buffer.get( ),
			buffer_size,
			&buffer_size
		);

		if ( !NT_SUCCESS( status ) )
			return nullptr;

		const auto modules = reinterpret_cast<rtl_process_modules_t*>( buffer.get( ) );
		for ( auto idx = 0u; idx < modules->m_count; ++idx ) {
			const auto current_module_name = std::string(
				reinterpret_cast<char*>( modules->m_modules[ idx ].m_full_path ) +
				modules->m_modules[ idx ].m_offset_to_file_name
			);

			if ( !_stricmp( current_module_name.c_str( ), module_name ) ) {
				const auto module_base = reinterpret_cast<std::uint64_t>(
					modules->m_modules[ idx ].m_image_base );
				return std::make_unique< c_module >( module_base );
			}
		}

		return nullptr;
	}
}
