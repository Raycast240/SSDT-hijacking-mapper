#pragma once

namespace handler {
    long crash_handler( EXCEPTION_POINTERS* ) {
        if ( g_syscall )
            g_syscall->emergency_restore( );
        cleanup::full_teardown( false );
        logging::status( oxorany( "failed" ) );
        return true;
    }
}
