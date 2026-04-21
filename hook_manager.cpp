#pragma once

#include <Windows.h>
#include "External/MinHook/MinHook.h"

namespace utils {
    namespace simple_hook_manager {

        template <typename Fn>
        inline bool create( void* target, Fn detour, Fn* original )
        {
            if ( !target || !detour || !original )
                return false;

            if ( MH_CreateHook( target, reinterpret_cast< LPVOID >( detour ), reinterpret_cast< LPVOID* >( original ) ) != MH_OK )
                return false;

            return MH_EnableHook( target ) == MH_OK;
        }

        inline void remove( void* target )
        {
            if ( !target )
                return;

            MH_DisableHook( target );
            MH_RemoveHook( target );
        }

    }
}
