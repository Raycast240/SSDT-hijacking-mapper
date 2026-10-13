#pragma once

namespace service {
	class c_service {
	public:
		bool create( ) {
			if ( !load_driver_privilage( true ) ) {
				logging::print( oxorany( "Failed to enable SeLoadDriverPrivilege" ) );
				return false;
			}

			utility::gen_rnd_str( m_driver_name );

			if ( !cleanup::build_paths( m_driver_name, cleanup::g_ctx ) ) {
				logging::print( oxorany( "Failed to build service paths" ) );
				load_driver_privilage( false );
				return false;
			}

			if ( !install_service(
				m_driver_name,
				cleanup::g_ctx.image_path_win32,
				cleanup::g_ctx.image_path_nt ) ) {

				load_driver_privilage( false );
				cleanup::g_ctx.loaded = false;
				return false;
			}

			cleanup::g_ctx.loaded = true;
			return true;
		}

	private:
		wchar_t m_driver_name[ 20 ]{ };
	};
}
