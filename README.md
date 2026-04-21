# r6hookmethod
Hooking method using minhook and spoof_call


how to use

```cpp

namespace calls {
inline bool ( __fastcall* server_position_manager )( __int64, __int64 ) = nullptr;
inline void ( __fastcall* pawn_action )( Scimitar::pawn*, __int64 ) = nullptr;
}

namespace hooks {
inline void* rva( uintptr_t offset )
{
    return reinterpret_cast< void* >( utils::memory::image_base + offset );
}

inline uintptr_t local_pawn_cached = 0;
bool __fastcall server_position_manager( __int64 rcx, __int64 rdx );
void __fastcall pawn_action( Scimitar::pawn* pawn, __int64 action );
inline void* server_position_hook_target = nullptr;
inline void* pawn_action_hook_target = nullptr;
inline bool pawn_action_hook_enabled = false;

inline void init( )
{
    server_position_hook_target = rva( 0xFB03A0 );
    utils::simple_hook_manager::create( server_position_hook_target, &hooks::server_position_manager, &calls::server_position_manager );
    pawn_action_hook_target = rva( 0xF93010 );
    pawn_action_hook_enabled = utils::simple_hook_manager::create( pawn_action_hook_target, &hooks::pawn_action, &calls::pawn_action );
}

inline void uninit( )
{
    if ( server_position_hook_target ) {
        utils::simple_hook_manager::remove( server_position_hook_target );
        server_position_hook_target = nullptr;
    }
    if ( pawn_action_hook_target ) {
        utils::simple_hook_manager::remove( pawn_action_hook_target );
        pawn_action_hook_target = nullptr;
    }
    pawn_action_hook_enabled = false;
}
}

namespace hk {
inline void init( ) { hooks::init( ); }
inline void uninit( ) { hooks::uninit( ); }
}
```
