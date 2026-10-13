#pragma once

#include <vector>
#include <fstream>
#include <cstring>
#include <winternl.h>

namespace map {
namespace buddy {

	struct pattern_t {
		const char* name;
		const std::uint8_t* bytes;
		const char* mask;
		std::size_t length;
	};

	inline const std::uint8_t k_pat_raw_long[ ] = {
		0x48, 0x8B, 0x11, 0x8B, 0x41, 0x24, 0x25, 0x00, 0x00, 0xFF, 0x03, 0x48, 0xD1, 0xEA
	};
	inline const char k_mask_raw_long[ ] = "xxxxxxxxxxxxxx";

	inline const std::uint8_t k_pat_raw_med[ ] = {
		0x48, 0x8B, 0x11, 0x8B, 0x41, 0x00, 0x25, 0x00, 0x00, 0xFF, 0x03
	};
	inline const char k_mask_raw_med[ ] = "xxxxx?xxxxx";

	inline const std::uint8_t k_pat_pidsafe_eax[ ] = {
		0x48, 0x8B, 0x01,
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF,
		0x48, 0xC1, 0xE8, 0x0D,
		0x48, 0x83, 0xE0, 0xF0,
		0x48, 0x0B, 0xC1,
		0x8B, 0x80, 0x00, 0x00, 0x00, 0x00
	};
	inline const char k_mask_pidsafe_eax[ ] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

	inline const std::uint8_t k_pat_pidsafe_rax[ ] = {
		0x48, 0x8B, 0x01,
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF,
		0x48, 0xC1, 0xE8, 0x0D,
		0x48, 0x83, 0xE0, 0xF0,
		0x48, 0x0B, 0xC1,
		0x48, 0x8B, 0x80, 0x00, 0x00, 0x00, 0x00
	};
	inline const char k_mask_pidsafe_rax[ ] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

	inline constexpr std::size_t k_pidsafe_eax_disp = 26;
	inline constexpr std::size_t k_pidsafe_rax_disp = 27;

	inline bool match_at( const std::uint8_t* data, const std::uint8_t* pat, const char* mask, std::size_t len ) {
		for ( std::size_t i = 0; i < len; ++i ) {
			if ( mask[ i ] == 'x' && data[ i ] != pat[ i ] )
				return false;
		}
		return true;
	}

	inline void collect_hits(
		const std::uint8_t* base,
		std::size_t size,
		const pattern_t& pat,
		std::vector< std::size_t >& out_offsets
	) {
		if ( size < pat.length )
			return;
		const auto end = size - pat.length;
		for ( std::size_t off = 0; off <= end; ++off ) {
			if ( !match_at( base + off, pat.bytes, pat.mask, pat.length ) )
				continue;
			out_offsets.push_back( off );
			if ( out_offsets.size( ) > 1 )
				return;
		}
	}

	inline bool read_file_bytes( const std::string& path, std::vector< std::uint8_t >& out ) {
		std::ifstream f( path, std::ios::binary | std::ios::ate );
		if ( !f.is_open( ) )
			return false;
		const auto sz = static_cast<std::size_t>( f.tellg( ) );
		if ( sz < 0x200 )
			return false;
		f.seekg( 0 );
		out.resize( sz );
		f.read( reinterpret_cast<char*>( out.data( ) ), static_cast<std::streamsize>( sz ) );
		return static_cast<std::size_t>( f.gcount( ) ) == sz;
	}

	inline std::string system32_ntos_path( ) {
		char win[ MAX_PATH ]{};
		if ( !GetSystemDirectoryA( win, MAX_PATH ) )
			return {};
		std::string p = win;
		if ( !p.empty( ) && p.back( ) != '\\' )
			p += '\\';
		p += "ntoskrnl.exe";
		return p;
	}

	inline std::uint32_t scan_pe_for_unique_rva(
		const std::vector< std::uint8_t >& pe,
		const pattern_t& pat,
		int* out_hit_count = nullptr
	) {
		if ( pe.size( ) < 0x200 )
			return 0;

		const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>( pe.data( ) );
		if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
			return 0;
		if ( static_cast<std::size_t>( dos->e_lfanew ) + sizeof( IMAGE_NT_HEADERS64 ) > pe.size( ) )
			return 0;

		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>( pe.data( ) + dos->e_lfanew );
		if ( nt->Signature != IMAGE_NT_SIGNATURE )
			return 0;
		if ( nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return 0;

		const auto* sec = IMAGE_FIRST_SECTION( nt );
		const auto nsec = nt->FileHeader.NumberOfSections;

		std::vector< std::uint32_t > rvas;
		for ( std::uint16_t i = 0; i < nsec; ++i ) {
			const auto& s = sec[ i ];
			const bool exec = ( s.Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0
				|| ( s.Characteristics & IMAGE_SCN_CNT_CODE ) != 0;
			if ( !exec )
				continue;

			const auto raw = static_cast<std::size_t>( s.PointerToRawData );
			const auto raw_sz = static_cast<std::size_t>( s.SizeOfRawData );
			if ( !raw || !raw_sz || raw + raw_sz > pe.size( ) )
				continue;

			std::vector< std::size_t > offs;
			collect_hits( pe.data( ) + raw, raw_sz, pat, offs );
			for ( auto off : offs ) {
				rvas.push_back( static_cast<std::uint32_t>( s.VirtualAddress + off ) );
				if ( rvas.size( ) > 1 )
					break;
			}
			if ( rvas.size( ) > 1 )
				break;
		}

		if ( out_hit_count )
			*out_hit_count = static_cast<int>( rvas.size( ) );
		if ( rvas.size( ) != 1 )
			return 0;
		return rvas[ 0 ];
	}

	inline bool pe_has_pidsafe_decode( const std::vector< std::uint8_t >& pe, std::uint32_t pdb_pid_off );

	inline std::uint64_t resolve_callable( std::uint64_t ntos_kernel_base, const char** out_how = nullptr, std::uint32_t pdb_pid_off = 0 ) {
		if ( !ntos_kernel_base ) {
			if ( out_how ) *out_how = "none";
			return 0;
		}

		const auto from_pdb = g_pdb->get_symbol_address( oxorany( "MiGetPageTablePfnBuddyRaw" ) );
		if ( from_pdb ) {
			if ( out_how ) *out_how = "pdb-raw";
			return from_pdb;
		}

		const auto path = system32_ntos_path( );
		if ( path.empty( ) ) {
			if ( out_how ) *out_how = "none";
			return 0;
		}

		std::vector< std::uint8_t > pe;
		if ( !read_file_bytes( path, pe ) ) {
			if ( out_how ) *out_how = "none";
			return 0;
		}

		const pattern_t bank[ ] = {
			{ "raw-long", k_pat_raw_long, k_mask_raw_long, sizeof( k_pat_raw_long ) },
			{ "raw-med",  k_pat_raw_med,  k_mask_raw_med,  sizeof( k_pat_raw_med ) },
		};

		for ( const auto& pat : bank ) {
			int hits = 0;
			const auto rva = scan_pe_for_unique_rva( pe, pat, &hits );
			if ( hits > 1 ) {
				logging::print( oxorany( "Buddy pattern '%s' matched %d times; rejected" ), pat.name, hits );
				continue;
			}
			if ( !rva )
				continue;

			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>( pe.data( ) );
			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>( pe.data( ) + dos->e_lfanew );
			if ( rva >= nt->OptionalHeader.SizeOfImage )
				continue;

			if ( out_how ) *out_how = pat.name;
			return ntos_kernel_base + rva;
		}

		if ( pe_has_pidsafe_decode( pe, pdb_pid_off ) ) {
			if ( out_how ) *out_how = "inline-pidsafe";
			return 0;
		}

		if ( out_how ) *out_how = "none";
		return 0;
	}

	inline void collect_pid_disp_candidates( std::uint32_t pdb_pid_off, std::uint32_t* out, int* n ) {
		*n = 0;
		auto add = [ & ]( std::uint32_t v ) {
			if ( !v )
				return;
			for ( int i = 0; i < *n; ++i ) {
				if ( out[ i ] == v )
					return;
			}
			if ( *n < 4 )
				out[ ( *n )++ ] = v;
		};
		add( pdb_pid_off );
		add( 0x1d0u );
		add( 0x440u );
	}

	inline void patch_disp32( std::uint8_t* bytes, std::size_t at, std::uint32_t disp ) {
		bytes[ at ]     = static_cast<std::uint8_t>( disp );
		bytes[ at + 1 ] = static_cast<std::uint8_t>( disp >> 8 );
		bytes[ at + 2 ] = static_cast<std::uint8_t>( disp >> 16 );
		bytes[ at + 3 ] = static_cast<std::uint8_t>( disp >> 24 );
	}

	inline bool pe_has_pidsafe_decode( const std::vector< std::uint8_t >& pe, std::uint32_t pdb_pid_off ) {
		std::uint32_t cands[ 4 ]{};
		int n = 0;
		collect_pid_disp_candidates( pdb_pid_off, cands, &n );

		for ( int i = 0; i < n; ++i ) {
			std::uint8_t eax[ sizeof( k_pat_pidsafe_eax ) ];
			std::memcpy( eax, k_pat_pidsafe_eax, sizeof( eax ) );
			patch_disp32( eax, k_pidsafe_eax_disp, cands[ i ] );
			int hits = 0;
			const pattern_t p_eax{ "pidsafe-eax", eax, k_mask_pidsafe_eax, sizeof( eax ) };
			( void )scan_pe_for_unique_rva( pe, p_eax, &hits );
			if ( hits == 1 )
				return true;

			std::uint8_t rax[ sizeof( k_pat_pidsafe_rax ) ];
			std::memcpy( rax, k_pat_pidsafe_rax, sizeof( rax ) );
			patch_disp32( rax, k_pidsafe_rax_disp, cands[ i ] );
			hits = 0;
			const pattern_t p_rax{ "pidsafe-rax", rax, k_mask_pidsafe_rax, sizeof( rax ) };
			( void )scan_pe_for_unique_rva( pe, p_rax, &hits );
			if ( hits == 1 )
				return true;
		}
		return false;
	}

	inline bool has_verified_inline_decode( std::uint32_t pdb_pid_off = 0 ) {
		const auto path = system32_ntos_path( );
		if ( path.empty( ) )
			return false;
		std::vector< std::uint8_t > pe;
		if ( !read_file_bytes( path, pe ) )
			return false;
		return pe_has_pidsafe_decode( pe, pdb_pid_off );
	}

	inline std::uint32_t os_build_number( ) {
		using rtl_get_version_t = LONG( NTAPI* )( PRTL_OSVERSIONINFOW );
		const auto ntdll = GetModuleHandleA( "ntdll.dll" );
		if ( !ntdll )
			return 0;
		const auto fn = reinterpret_cast<rtl_get_version_t>(
			GetProcAddress( ntdll, "RtlGetVersion" ) );
		if ( !fn )
			return 0;
		RTL_OSVERSIONINFOW vi{};
		vi.dwOSVersionInfoSize = sizeof( vi );
		if ( fn( &vi ) != 0 )
			return 0;
		return vi.dwBuildNumber;
	}

}
}
