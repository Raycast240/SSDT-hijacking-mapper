#pragma once

namespace logging {

    inline void spin_stop( ) { }

    inline void spin( const char* ) { }

    inline void banner( ) { }

    template<typename... Args>
    inline void print( const char*, Args... ) { }

    template<typename... Args>
    inline void money( const char*, Args... ) { }

    inline void status( const char* text ) {
        if ( !text || !*text )
            return;
        printf( "%s\n", text );
        fflush( stdout );
    }
}
