#pragma once
#include <type_traits>

namespace detail
{
	extern "C" void* _spoofer_stub( );

	template <typename Ret, typename... Args>
	static inline auto shellcode_stub_helper(
		const void* shell,
		Args... args
	) -> Ret
	{
		auto fn = ( Ret( * )( Args... ) )( shell );
		return fn( args... );
	}

	template <std::size_t Argc, typename>
	struct argument_remapper
	{
		// At least 5 params
		template<
			typename Ret,
			typename First,
			typename Second,
			typename Third,
			typename Fourth,
			typename... Pack
		>
		static auto do_call(
			const void* shell,
			void* shell_param,
			First first,
			Second second,
			Third third,
			Fourth fourth,
			Pack... pack
		) -> Ret
		{
			return shellcode_stub_helper<
				Ret,
				First,
				Second,
				Third,
				Fourth,
				void*,
				void*,
				Pack...
			>(
				shell,
				first,
				second,
				third,
				fourth,
				shell_param,
				nullptr,
				pack...
			);
		}
	};

	template <std::size_t Argc>
	struct argument_remapper<Argc, std::enable_if_t<Argc <= 4>>
	{
		// 4 or less params
		template<
			typename Ret,
			typename First = void*,
			typename Second = void*,
			typename Third = void*,
			typename Fourth = void*
		>
		static auto do_call(
			const void* shell,
			void* shell_param,
			First first = First{ },
			Second second = Second{ },
			Third third = Third{ },
			Fourth fourth = Fourth{ }
		) -> Ret
		{
			return shellcode_stub_helper<
				Ret,
				First,
				Second,
				Third,
				Fourth,
				void*,
				void*
			>(
				shell,
				first,
				second,
				third,
				fourth,
				shell_param,
				nullptr
			);
		}
	};
}

namespace utils
{
	inline void* trampoline_jmp{ };
	template <typename result, typename... arguments>
	static inline auto spoof_call(
		result( *fn )( arguments... ),
		arguments... args
	) -> result
	{
		struct shell_params
		{
			const void* trampoline;
			void* function;
			void* register_;
		};

		shell_params p = { trampoline_jmp, reinterpret_cast< void* >( fn ) };
		using mapper = detail::argument_remapper<sizeof...( arguments ), void>;
		return mapper::template do_call<result, arguments...>( ( const void* ) &detail::_spoofer_stub, &p, args... );
	}

	template<typename Ret, typename... Args>
	static inline Ret spoof_call_virtual( int index, void* Instance, Args... args )
	{
		if ( !Instance )
			return Ret{ };

		void** vTable = *( void*** ) ( Instance );

		if ( !vTable || index < 0 )
		{
			return Ret{ };
		}

		using Orig = Ret( * )( void*, Args... );
		Orig Func = reinterpret_cast< Orig >( vTable[ index ] );

		return spoof_call<Ret>( Func, Instance, std::forward<Args>( args )... );
	}
}
