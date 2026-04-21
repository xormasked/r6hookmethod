# r6hookmethod
Hooking method using minhook and spoof_call



Usage

```cpp
namespace base_calls {

    inline bool( __fastcall* hook_a )( __int64, __int64 ) = nullptr; // original function pointer set by minhook.

}

namespace base_hooks {

    bool __fastcall hook_a( __int64 rcx, __int64 rdx ); // match with the function ur hooking.

    inline void init( )
    {

        const auto hook_a_target = reinterpret_cast< void* >( utils::memory::image_base + 0x0 ); // replace 0x0 with ur hook rva.

        utils::simple_hook_manager::create( hook_a_target, &base_hooks::hook_a, &base_calls::hook_a ); // install detour and save original into base_calls::hook_a.
    }

    inline void uninit( )
    {
        const auto hook_a_target = reinterpret_cast< void* >( utils::memory::image_base + 0x0 ); // remember to replace 0x0 with the same hook rva as hook_a_target.

        utils::simple_hook_manager::remove( hook_a_target ); // remove on unload
    }
}
```

this is how u can edit the function to do what you want it to do

```cpp
bool __fastcall base_hooks::hook_a( __int64 rcx, __int64 rdx ) // change based on how many args u have on ur hooked function
{
    if ( !base_calls::hook_a || !utils::trampoline_jmp )
        return false;

    const bool ret = utils::spoof_call<bool>( base_calls::hook_a, rcx, rdx ); // USE SPOOFCALL TO CALL THE FUNCTION!!!!!, 99% of the time you WILL crash if you do not.

    // ex 1: write to memory using an argument as a base address, or change arg if u want to.
    if ( rdx )
    {
        WPM<float>( rdx + 0x10, 0.f ); // change offset/value for ur use case.
    }

    // ex 2: print argument values for quick debug, or to get around encryption.
    std::printf( "[hook_a] arg0=0x%llX arg1=0x%llX\n",
        static_cast< unsigned long long >( rcx ),
        static_cast< unsigned long long >( rdx ) );

    return ret;
}
```
