#pragma once

#include "snap.hpp"
#include "user.hpp"
#include "unload.hpp"
#include "cache.hpp"
#include "bucket.hpp"
#include "filter.hpp"

namespace cleanup {

inline void kernel_residual_strip( const char* phase_tag ) {
    if ( g_driver ) {
        const auto h = g_driver->get_handle( );
        g_ctx.device_open = ( h && h != INVALID_HANDLE_VALUE );
    }

    const bool can_k1 =
        g_ctx.device_open &&
        g_ctx.paging_ready &&
        g_driver &&
        g_paging &&
        g_pdb;

    const bool can_k234 =
        can_k1 &&
        g_ctx.syscall_ready &&
        g_syscall;

    logging::print( oxorany( "Cleanup [%s]: k1=%d k2-k4=%d device=%d paging=%d syscall=%d" ),
        phase_tag ? phase_tag : "?",
        can_k1 ? 1 : 0,
        can_k234 ? 1 : 0,
        g_ctx.device_open ? 1 : 0,
        g_ctx.paging_ready ? 1 : 0,
        g_ctx.syscall_ready ? 1 : 0 );

    if ( !can_k1 ) {
        logging::print( oxorany( "Cleanup skipped (device and paging are required)" ) );
        return;
    }

    try {
        if ( mm::prep_skip_unload_record( g_ctx ) )
            logging::print( oxorany( "Cleanup K1 (MmUnloaded) succeeded" ) );
        else
            logging::print( oxorany( "Cleanup K1 skipped (residual may remain)" ) );
    }
    catch ( ... ) { logging::print( oxorany( "Cleanup K1 raised an exception; continuing" ) ); }

    if ( !can_k234 ) {
        logging::print( oxorany( "Cleanup K2-K4 skipped (kernel execution is not ready)" ) );
        return;
    }

    try {
        piddb::clear( g_ctx );
        logging::print( oxorany( "Cleanup K2 (PiDDB) complete" ) );
    }
    catch ( ... ) { logging::print( oxorany( "Cleanup K2 raised an exception; continuing" ) ); }

    try {
        hash_bucket::clear( g_ctx );
        logging::print( oxorany( "Cleanup K3 (hash bucket) complete" ) );
    }
    catch ( ... ) { logging::print( oxorany( "Cleanup K3 raised an exception; continuing" ) ); }

    try {
        wdfilter::clear( g_ctx );
        logging::print( oxorany( "Cleanup K4 (WdFilter) complete" ) );
    }
    catch ( ... ) { logging::print( oxorany( "Cleanup K4 raised an exception; continuing" ) ); }
}

inline void full_teardown( bool kernel_ready ) {
    const bool reentry = g_ctx.teardown_started;
    if ( !reentry )
        g_ctx.teardown_started = true;

    if ( g_driver ) {
        const auto h = g_driver->get_handle( );
        g_ctx.device_open = ( h && h != INVALID_HANDLE_VALUE );
    }

    if ( !reentry && kernel_ready )
        kernel_residual_strip( oxorany( "teardown" ) );
    else if ( !reentry )
        logging::print( oxorany( "Cleanup skipped (kernel is not ready)" ) );
    else
        logging::print( oxorany( "Cleanup re-entered; finishing usermode teardown" ) );

    if ( g_driver ) {
        g_driver->unload( );
        g_ctx.device_open = false;
        logging::print( oxorany( "Closed driver handle" ) );
    }

    usermode::teardown_after_close( g_ctx );

    service::load_driver_privilage( false );

    g_ctx.paging_ready = false;
    g_ctx.syscall_ready = false;
    g_ctx.loaded = false;

    logging::print( oxorany( "Teardown complete" ) );
}

inline void early_teardown( ) {
    if ( g_ctx.teardown_started ) {
        if ( g_driver )
            g_driver->unload( );
        g_ctx.device_open = false;
        if ( g_ctx.loaded || g_ctx.service_name[ 0 ] )
            usermode::teardown_after_close( g_ctx );
        service::load_driver_privilage( false );
        g_ctx.paging_ready = false;
        g_ctx.syscall_ready = false;
        g_ctx.loaded = false;
        logging::print( oxorany( "Early teardown re-entry complete" ) );
        return;
    }
    g_ctx.teardown_started = true;

    if ( g_driver )
        g_driver->unload( );
    g_ctx.device_open = false;

    if ( g_ctx.loaded || g_ctx.service_name[ 0 ] )
        usermode::teardown_after_close( g_ctx );

    service::load_driver_privilage( false );
    g_ctx.paging_ready = false;
    g_ctx.syscall_ready = false;
    g_ctx.loaded = false;
    logging::print( oxorany( "Early teardown complete" ) );
}

}
