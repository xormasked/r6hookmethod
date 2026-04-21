# r6hookmethod
Hooking method using minhook and spoof_call

Usage:

```cpp

namespace base_calls {
    // Original function pointer set by MinHook.
    inline bool( __fastcall* hook_a )( __int64, __int64 ) = nullptr;
}

namespace base_hooks {
    // Match this signature to the function you are hooking.
    bool __fastcall hook_a( __int64 arg0, __int64 arg1 );

    inline void init( )
    {
        // Replace 0x0 with your target RVA.
        const auto hook_a_target = reinterpret_cast< void* >( utils::memory::image_base + 0x0 );

        // Install detour and save original into base_calls::hook_a.
        utils::simple_hook_manager::create( hook_a_target, &base_hooks::hook_a, &base_calls::hook_a );
    }

    inline void uninit( )
    {
        const auto hook_a_target = reinterpret_cast< void* >( utils::memory::image_base + 0x0 );

        // Remove detour on unload.
        utils::simple_hook_manager::remove( hook_a_target );
    }
}
```

This is how you can edit the hook to make the function do what you want to do:

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


