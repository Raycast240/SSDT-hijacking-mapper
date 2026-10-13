#pragma once

namespace utility {
	bool adjust_privilege( std::uint32_t privilege ) {
		auto ntdll = GetModuleHandleA( "ntdll.dll" );
		if ( !ntdll )
			return false;

		typedef NTSTATUS( __stdcall* rtl_adjust_privilege_fn )( DWORD, BOOL, INT, PBOOL );
		auto rtl_adjust_privilege = reinterpret_cast<rtl_adjust_privilege_fn>( GetProcAddress( ntdll, "RtlAdjustPrivilege" ) );

		BOOL was_enabled;
		auto status = rtl_adjust_privilege( privilege, TRUE, FALSE, &was_enabled );
		if ( status ) {
			logging::print( "Failed to acquire required privilege" );
			return false;
		}

		return true;
	}

	void gen_rnd_str( wchar_t* random_str ) {
		auto length = ( rand( ) % 12 ) + 8;
		for ( auto i = 0ull; i < length; i++ ) {
			switch ( rand( ) % 3 ) {
				case 0:
					random_str[ i ] = static_cast<wchar_t>( 'A' + rand( ) % 26 );
					break;

				case 1:
					random_str[ i ] = static_cast<wchar_t>( 'a' + rand( ) % 26 );
					break;

				case 2:
					random_str[ i ] = static_cast<wchar_t>( '0' + rand( ) % 10 );
					break;
			}
		}

		random_str[ length ] = 0;
	}

	bool is_physical_address_valid( std::uint64_t pa, std::size_t size ) {
		int regs[ 4 ]{};
		__cpuid( regs, 0x80000000 );
		unsigned max_ext = static_cast<unsigned>( regs[ 0 ] );
		unsigned phys_bits = 36;
		if ( max_ext >= 0x80000008 ) {
			__cpuid( regs, 0x80000008 );
			unsigned b = regs[ 0 ] & 0xFF;
			if ( b >= 32 && b <= 52 )
				phys_bits = b;
		}

		auto physical_mask = ( phys_bits >= 63 ) ? ~0ULL : ( ( 1ULL << phys_bits ) - 1ULL );
		if ( ( pa & ~physical_mask ) != 0 )
			return false;

		const auto end_pa = pa + ( size - 1 );
		if ( ( end_pa & ~physical_mask ) != 0 )
			return false;

		return true;
	}
}
