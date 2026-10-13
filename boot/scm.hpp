#pragma once
using nt_load_driver_t = NTSTATUS( __fastcall* )( PUNICODE_STRING );

namespace service {

    bool delete_service_key_only( const wchar_t* service_name );

    bool load_driver_privilage( bool enabled ) {
        TOKEN_PRIVILEGES privilege{};
        privilege.PrivilegeCount = 1;

        if ( !LookupPrivilegeValueA(
            nullptr,
            oxorany( "SeLoadDriverPrivilege" ),
            &privilege.Privileges[ 0 ].Luid ) ) {
            logging::print( oxorany( "LookupPrivilegeValue failed: 0x%x" ), GetLastError( ) );
            return false;
        }

        HANDLE token = nullptr;
        if ( !OpenProcessToken(
            GetCurrentProcess( ),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &token ) ) {
            logging::print( oxorany( "OpenProcessToken failed: 0x%x" ), GetLastError( ) );
            return false;
        }

        privilege.Privileges[ 0 ].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

        auto result = AdjustTokenPrivileges(
            token,
            FALSE,
            &privilege,
            sizeof( privilege ),
            nullptr,
            nullptr
        );

        const auto adj_err = GetLastError( );

        bool ok = result && adj_err != ERROR_NOT_ALL_ASSIGNED;
        if ( !ok ) {
            result = AdjustTokenPrivileges(
                token,
                TRUE,
                &privilege,
                sizeof( privilege ),
                nullptr,
                nullptr
            );
            ok = result && GetLastError( ) != ERROR_NOT_ALL_ASSIGNED;
        }

        if ( token )
            NtClose( token );

        if ( !ok ) {
            logging::print( oxorany( "AdjustTokenPrivileges failed: 0x%x" ), adj_err );
            return false;
        }

        return true;
    }

    bool create_service( const wchar_t* service_name, const wchar_t* registry_path ) {
        if ( !service_name || !registry_path ) {
            logging::print( oxorany( "Invalid service name or registry path" ) );
            return false;
        }

        HKEY service_key = nullptr;
        auto result = RegOpenKeyA(
            HKEY_LOCAL_MACHINE,
            oxorany( "system\\CurrentControlSet\\Services" ),
            &service_key
        );

        if ( result != ERROR_SUCCESS ) {
            logging::print( oxorany( "Failed to open services key: %d" ), result );
            return false;
        }

        HKEY service_config_key = nullptr;
        result = RegCreateKeyW(
            service_key,
            service_name,
            &service_config_key
        );

        if ( result != ERROR_SUCCESS ) {
            RegCloseKey( service_key );
            logging::print( oxorany( "Failed to create service key: %d" ), result );
            return false;
        }

        const auto path_len = static_cast<DWORD>( ( std::wcslen( registry_path ) + 1 ) * sizeof( wchar_t ) );
        result = RegSetValueExW(
            service_config_key,
            oxorany( L"ImagePath" ),
            0,
            REG_EXPAND_SZ,
            reinterpret_cast<const std::uint8_t*>( registry_path ),
            path_len
        );

        if ( result != ERROR_SUCCESS ) {
            RegCloseKey( service_config_key );
            RegCloseKey( service_key );
            logging::print( oxorany( "Failed to set ImagePath: %d" ), result );
            delete_service_key_only( service_name );
            return false;
        }

        const DWORD type = 1;
        result = RegSetValueExA(
            service_config_key,
            oxorany( "Type" ),
            0,
            REG_DWORD,
            reinterpret_cast<const std::uint8_t*>( &type ),
            sizeof( type )
        );

        RegCloseKey( service_config_key );
        RegCloseKey( service_key );

        if ( result != ERROR_SUCCESS ) {
            logging::print( oxorany( "Failed to set service Type: %d" ), result );
            delete_service_key_only( service_name );
            return false;
        }

        return true;
    }

    UNICODE_STRING build_driver_path( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            return {};
        }

        static wchar_t registry_path[ 80 ]{};
        std::memset( registry_path, 0, sizeof( registry_path ) );
        std::wcscat( registry_path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" );
        std::wcscat( registry_path, service_name );

        UNICODE_STRING driver_path{};
        driver_path.Length = USHORT( std::wcslen( registry_path ) << 1 );
        driver_path.Buffer = registry_path;
        driver_path.MaximumLength = driver_path.Length + 2;

        return driver_path;
    }

    bool delete_service_key_only( const wchar_t* service_name ) {
        if ( !service_name || !service_name[ 0 ] )
            return false;

        HKEY services_key = nullptr;
        auto result = RegOpenKeyA(
            HKEY_LOCAL_MACHINE,
            oxorany( "SYSTEM\\CurrentControlSet\\Services" ),
            &services_key
        );
        if ( result != ERROR_SUCCESS )
            return false;

        result = RegDeleteKeyW( services_key, service_name );
        RegCloseKey( services_key );
        return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
    }

    void uninstall_orphan_log_services( const wchar_t* skip_name = nullptr ) {
        HKEY services_key = nullptr;
        if ( RegOpenKeyA(
            HKEY_LOCAL_MACHINE,
            oxorany( "SYSTEM\\CurrentControlSet\\Services" ),
            &services_key ) != ERROR_SUCCESS ) {
            return;
        }

        wchar_t temp_path[ MAX_PATH ]{};
        if ( !GetTempPathW( MAX_PATH, temp_path ) || !temp_path[ 0 ] ) {
            RegCloseKey( services_key );
            return;
        }

        wchar_t temp_nt[ MAX_PATH ]{};
        _snwprintf_s( temp_nt, _TRUNCATE, L"\\??\\%s", temp_path );

        DWORD index = 0;
        wchar_t service_name[ MAX_PATH ];

        while ( RegEnumKeyW( services_key, index, service_name, MAX_PATH ) == ERROR_SUCCESS ) {
            bool deleted = false;
            HKEY service_key = nullptr;
            if ( RegOpenKeyW( services_key, service_name, &service_key ) == ERROR_SUCCESS ) {
                wchar_t image_path[ MAX_PATH ]{};
                DWORD path_size = sizeof( image_path );
                DWORD path_type = 0;

                if ( RegQueryValueExW( service_key, oxorany( L"ImagePath" ), nullptr, &path_type,
                    reinterpret_cast<LPBYTE>( image_path ), &path_size ) == ERROR_SUCCESS ) {

                    DWORD svc_type = 0;
                    DWORD svc_type_sz = sizeof( svc_type );
                    DWORD svc_type_reg = 0;
                    const bool type_ok =
                        RegQueryValueExA( service_key, oxorany( "Type" ), nullptr, &svc_type_reg,
                            reinterpret_cast<LPBYTE>( &svc_type ), &svc_type_sz ) == ERROR_SUCCESS &&
                        svc_type == 1;

                    const auto plen = wcslen( image_path );
                    const bool ends_log = plen >= 4 && _wcsicmp( image_path + plen - 4, L".log" ) == 0;
                    const bool under_temp =
                        ( wcsncmp( image_path, L"\\??\\", 4 ) == 0 ) &&
                        ( _wcsnicmp( image_path, temp_nt, wcslen( temp_nt ) ) == 0 );

                    if ( type_ok && ends_log && under_temp ) {
                        const bool is_skip = skip_name && !_wcsicmp( service_name, skip_name );
                        if ( !is_skip ) {
                            RegCloseKey( service_key );
                            service_key = nullptr;

                            using nt_unload_driver_t = NTSTATUS( __stdcall* )( PUNICODE_STRING );
                            auto* nt_unload_drv = reinterpret_cast<nt_unload_driver_t>(
                                GetProcAddress( GetModuleHandleA( oxorany( "ntdll.dll" ) ), oxorany( "NtUnloadDriver" ) )
                            );
                            if ( nt_unload_drv ) {
                                auto p = build_driver_path( service_name );
                                if ( p.Buffer )
                                    nt_unload_drv( &p );
                            }

                            const wchar_t* win32 = image_path;
                            if ( wcsncmp( image_path, L"\\??\\", 4 ) == 0 )
                                win32 = image_path + 4;
                            for ( int i = 0; i < 5; ++i ) {
                                if ( DeleteFileW( win32 ) || GetLastError( ) == ERROR_FILE_NOT_FOUND )
                                    break;
                                Sleep( 50 );
                            }

                            if ( RegDeleteKeyW( services_key, service_name ) == ERROR_SUCCESS )
                                deleted = true;
                        }
                    }
                }
                if ( service_key )
                    RegCloseKey( service_key );
            }

            if ( !deleted )
                index++;
        }

        RegCloseKey( services_key );
    }

    bool install_service( const wchar_t* service_name,
        const wchar_t* win32_path_in = nullptr,
        const wchar_t* nt_path_in = nullptr ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            logging::print( oxorany( "Invalid service name" ) );
            return false;
        }

        {
            auto h = CreateFileW(
                oxorany( L"\\\\.\\EBIoDispatch" ),
                GENERIC_READ | GENERIC_WRITE,
                0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
            );
            if ( h && h != INVALID_HANDLE_VALUE ) {
                CloseHandle( h );
                logging::print( oxorany( "Device already present; unload or reboot first" ) );
                return false;
            }
        }

        wchar_t registry_path[ MAX_PATH ]{};
        wchar_t win32_path[ MAX_PATH ]{};

        if ( win32_path_in && win32_path_in[ 0 ] && nt_path_in && nt_path_in[ 0 ] ) {
            wcsncpy_s( win32_path, win32_path_in, _TRUNCATE );
            wcsncpy_s( registry_path, nt_path_in, _TRUNCATE );
        } else {
            if ( GetTempPathW( MAX_PATH, win32_path ) == 0 ) {
                logging::print( oxorany( "Failed to resolve temporary path" ) );
                return false;
            }
            std::wcscat( win32_path, service_name );
            std::wcscat( win32_path, oxorany( L".log" ) );
            std::wcscpy( registry_path, oxorany( L"\\??\\" ) );
            std::wcscat( registry_path, win32_path );
        }

        HANDLE file_handle = CreateFileW(
            win32_path,
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY,
            nullptr
        );

        if ( file_handle == INVALID_HANDLE_VALUE ) {
            logging::print( oxorany( "Failed to create driver image file" ) );
            return false;
        }

        DWORD bytes_written = 0;
        if ( !WriteFile(
            file_handle,
            driver_bytes,
            sizeof( driver_bytes ),
            &bytes_written,
            nullptr
        ) || bytes_written != sizeof( driver_bytes ) ) {
            CloseHandle( file_handle );
            DeleteFileW( win32_path );
            logging::print( oxorany( "Failed to write driver image file" ) );
            return false;
        }
        CloseHandle( file_handle );

        if ( !create_service( service_name, registry_path ) ) {
            logging::print( oxorany( "Failed to register service" ) );
            delete_service_key_only( service_name );
            DeleteFileW( win32_path );
            return false;
        }

        auto driver_nt_name = build_driver_path( service_name );
        if ( !driver_nt_name.Buffer ) {
            logging::print( oxorany( "Failed to build driver registry path" ) );
            delete_service_key_only( service_name );
            DeleteFileW( win32_path );
            return false;
        }

        auto* nt_load_drv = reinterpret_cast<nt_load_driver_t>(
            GetProcAddress(
                GetModuleHandleA( oxorany( "ntdll.dll" ) ),
                oxorany( "NtLoadDriver" ) )
            );

        if ( !nt_load_drv ) {
            logging::print( oxorany( "Failed to resolve NtLoadDriver" ) );
            delete_service_key_only( service_name );
            DeleteFileW( win32_path );
            return false;
        }

        auto status = nt_load_drv( &driver_nt_name );
        if ( status == 0xc0000035 ) {
            logging::print( oxorany( "A conflicting service is already loaded" ) );

            delete_service_key_only( service_name );
            DeleteFileW( win32_path );
            uninstall_orphan_log_services( nullptr );
            logging::print( oxorany( "Restart the system and try again" ) );
            return false;
        }

        if ( status != 0 ) {
            logging::print( oxorany( "NtLoadDriver failed: %x" ), status );
            delete_service_key_only( service_name );
            DeleteFileW( win32_path );
            return false;
        }

        logging::print( oxorany( "Service installed successfully" ) );
        return true;
    }
}
