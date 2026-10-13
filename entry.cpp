#include <kit/prelude.hpp>

int main( int argc, char** argv ) {
	SetConsoleTitleA( oxorany( "mapper" ) );
	SetUnhandledExceptionFilter( handler::crash_handler );

	auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
	DWORD mode = 0;
	if ( GetConsoleMode( std_handle, &mode ) ) {
		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
		SetConsoleMode( std_handle, mode );
	}

	if ( !utility::adjust_privilege( 20 ) ) {
		logging::status( oxorany( "failed" ) );
		return std::getchar( );
	}

	if ( argc < 2 ) {
		logging::status( oxorany( "usage: mapper <path>" ) );
		return std::getchar( );
	}

	if ( !g_pdb->load( ) ) {
		logging::status( oxorany( "failed" ) );
		return std::getchar( );
	}

	if ( !g_pdb->get_symbol_address( oxorany( "PiDDBLock" ) ) ||
		 !g_pdb->get_symbol_address( oxorany( "PiDDBCacheTable" ) ) ||
		 !g_pdb->get_symbol_address( oxorany( "KeServiceDescriptorTable" ) ) ||
		 !g_pdb->get_symbol_address( oxorany( "ExAcquireResourceExclusiveLite" ) ) ||
		 !g_pdb->get_symbol_address( oxorany( "ExReleaseResourceLite" ) ) ||
		 !g_pdb->get_symbol_address( oxorany( "RtlLookupElementGenericTableAvl" ) ) ||
		 !g_pdb->get_symbol_address( oxorany( "RtlDeleteElementGenericTableAvl" ) ) ) {
		logging::status( oxorany( "failed" ) );
		return std::getchar( );
	}

	if ( !g_service->create( ) ) {
		logging::status( oxorany( "failed" ) );
		return std::getchar( );
	}

	if ( !g_driver->initialize( ) ) {
		logging::status( oxorany( "failed" ) );
		cleanup::early_teardown( );
		return std::getchar( );
	}
	cleanup::g_ctx.device_open = true;

	if ( !g_paging->setup( ) ) {
		logging::status( oxorany( "failed" ) );
		cleanup::full_teardown( false );
		return std::getchar( );
	}
	cleanup::g_ctx.paging_ready = true;

	if ( !g_syscall->setup( ) ) {
		logging::status( oxorany( "failed" ) );
		cleanup::full_teardown( true );
		return std::getchar( );
	}
	cleanup::g_ctx.syscall_ready = true;

	cleanup::kernel_residual_strip( oxorany( "post-load" ) );

	auto dependency = std::make_shared< map::c_dependency >( argv[ 1 ] );
	if ( !dependency->load( ) ) {
		logging::status( oxorany( "failed" ) );
		cleanup::full_teardown( true );
		return std::getchar( );
	}

	auto map = std::make_unique< map::c_map >( dependency );
	if ( !map->create( ) ) {
		logging::status( oxorany( "failed" ) );
		cleanup::full_teardown( true );
		return std::getchar( );
	}

	if ( !map->execute( ) ) {
		logging::status( oxorany( "failed" ) );
		cleanup::full_teardown( true );
		return std::getchar( );
	}

	if ( !g_syscall->verify_restored( ) ) {
		if ( !g_syscall->force_restore( ) ) {
			logging::status( oxorany( "failed" ) );
			cleanup::full_teardown( true );
			return std::getchar( );
		}
	}

	cleanup::full_teardown( true );
	logging::status( oxorany( "done" ) );
	return std::getchar( );
}
