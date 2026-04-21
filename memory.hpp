#pragma once
#ifndef _utils
#define _utils

#include <cstdint>
#include <cstring>
#include <vector>
#include <Windows.h>
#include <string>

#define WPM    utils::memory::Write
#define RPM    utils::memory::Read

#define IMG_BASE ( utils::memory::image_base )

namespace utils {

	namespace syscall
	{
		extern "C"
		{

			__forceinline auto __vm_protect( void*, void*, size_t*, std::uint32_t, std::uint32_t* ) -> uint32_t;


			__forceinline auto vm_protect( std::uint64_t address, size_t size, std::uint32_t protect, std::uint32_t* old_protect ) -> uint32_t
			{
				return __vm_protect(
					reinterpret_cast< void* >( -1 ),
					&address,
					&size,
					protect,
					old_protect
				) == 0 ? *old_protect : 0;
			}

			//__forceinline auto get_async_key_state(int vKey) -> std::uint16_t;


		}
	}

	namespace memory {



		template<typename T>
		void WriteProtected( uintptr_t address, T data )
		{
			uint32_t old{ };
			if ( !utils::syscall::vm_protect( address, sizeof( T ), PAGE_EXECUTE_READWRITE, &old ) )
				return;
			*( T* ) address = data;
			utils::syscall::vm_protect( address, sizeof( T ), old, &old );
		}



		template <typename T>
		__forceinline bool valid_pointer( T ptr )
		{
			__try
			{
				volatile auto result = *( uintptr_t* ) ptr;
			}
			__except ( EXCEPTION_EXECUTE_HANDLER )
			{
				return false;
			}

			return true;
		}

		template<typename R, typename T>
		__forceinline R call_virtual( T* self, std::size_t index ) {
			if ( !self || !valid_pointer( self ) ) return R{};
			void** vtable = *reinterpret_cast< void*** >( self );
			return reinterpret_cast< R( __fastcall* )( T* ) >( vtable[ index ] )( self );
		}

		template<typename R, typename T, typename A1>
		__forceinline R call_virtual( T* self, std::size_t index, A1 a1 ) {
			if ( !self || !valid_pointer( self ) ) return R{};
			void** vtable = *reinterpret_cast< void*** >( self );
			return reinterpret_cast< R( __fastcall* )( T*, A1 ) >( vtable[ index ] )( self, a1 );
		}

		template<typename R, typename T>
		__forceinline R Virtual( T* self, std::size_t index ) {
			return call_virtual<R, T>( self, index );
		}

		template<typename R, typename T, typename A1>
		__forceinline R Virtual( T* self, std::size_t index, A1 a1 ) {
			return call_virtual<R, T, A1>( self, index, a1 );
		}


		template<typename T>
		T Read( uintptr_t address ) {
			if ( IsBadReadPtr( ( void* ) address, sizeof( T ) ) ) {
				if constexpr ( std::is_pointer_v<T> ) {
					return nullptr;
				}
				else {
					return T{};
				}
			}
			return *reinterpret_cast< T* >( address );
		}

		template<typename T>
		void Write( uintptr_t address, T data ) {
			if ( IsBadReadPtr( ( void* ) address, sizeof( T ) ) ) return;
			if ( IsBadWritePtr( ( LPVOID ) address, sizeof( T ) ) ) return;
			*( T* ) address = data;
		}


		template<typename T>
		T ReadPtr( uintptr_t base, std::vector<uintptr_t> offsets ) {
			for ( int i = 0; i < offsets.size( ); i++ ) {
				base = Read<uintptr_t>( base );
				base += offsets[ i ];
			}
			return Read<T>( base );
		}


		inline uintptr_t GetAddr( uintptr_t base, std::vector<uintptr_t> offsets ) {
			for ( int i = 0; i < offsets.size( ); i++ ) {
				base = Read<uintptr_t>( base );
				if ( !base ) return 0;
				base += offsets[ i ];
				if ( !base ) return 0;
			}
			return base;
		}

		template<typename T>
		void WritePtr( uintptr_t base, std::vector<uintptr_t> offsets, T data ) {
			base = GetAddr( base, offsets );
			if ( IsBadWritePtr( ( LPVOID ) base, sizeof( T ) ) ) return;
			if ( IsBadReadPtr( ( void* ) base, sizeof( T ) ) ) return;
			Write<T>( base, data );
		}


		static std::vector<int> PatternToIntVector( const char* Pattern )
		{
			std::vector<int> PatternVector = std::vector<int>{};

			char* Start = const_cast< char* >( Pattern );

			char* End = const_cast< char* >( Pattern ) + strlen( Pattern );

			for ( char* Current = Start; Current < End; ++Current )
			{
				if ( *Current == '?' )
				{
					++Current;
					PatternVector.push_back( -69 );
				}
				else {
					PatternVector.push_back( strtoul( Current, &Current, 16 ) );
				}
			}

			return PatternVector;
		}

		template<typename T>
		static T PatternScan( const char* Pattern, uint64_t Start ) {
			const HMODULE GameModule = ( HMODULE ) Start;
			const IMAGE_DOS_HEADER* DOSHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( GameModule );
			const IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< long long >( GameModule ) + DOSHeader->e_lfanew );
			const size_t Size = NtHeaders->OptionalHeader.SizeOfImage;

			std::vector<int> PatternVector = PatternToIntVector( Pattern );

			uint8_t* Search = reinterpret_cast< uint8_t* >( Start );

			const size_t SizeOfPattern = PatternVector.size( );
			const int* PatternData = PatternVector.data( );

			for ( int i = 0; i < Size - SizeOfPattern; ++i ) {
				bool FoundSignature = true;

				for ( int j = 0; j < SizeOfPattern; ++j ) {
					if ( Search[ i + j ] != PatternData[ j ] && PatternData[ j ] != -69 ) {
						FoundSignature = false;
						break;
					}
				}

				if ( FoundSignature ) {
					return reinterpret_cast< T >( &Search[ i ] );
				}
			}

			return reinterpret_cast< T >( nullptr );
		}



		inline std::uint64_t image_base{ };
		inline std::uint32_t text_size{ };

		inline std::uint32_t rdata_size{ };
		inline std::uint32_t rdata_virtualaddress{ };



		inline std::uintptr_t scan_pattern( std::uint64_t base, std::uint32_t size, const char* signature )
		{
			static auto patternToByte = [ ] ( const char* pattern )
				{
					auto       bytes = std::vector<int>{ };
					const auto start = const_cast< char* >( pattern );
					const auto end = const_cast< char* >( pattern ) + strlen( pattern );

					for ( auto current = start; current < end; ++current )
					{
						if ( *current == '?' )
						{
							++current;
							if ( *current == '?' )
								++current;
							bytes.push_back( -1 );
						}
						else { bytes.push_back( strtoul( current, &current, 16 ) ); }
					}
					return bytes;
				};
			auto       patternBytes = patternToByte( signature );
			const auto scanBytes = reinterpret_cast< std::uint8_t* >( base );

			const auto s = patternBytes.size( );
			const auto d = patternBytes.data( );

			for ( auto i = 0ul; i < size - s; ++i )
			{
				bool found = true;
				for ( auto j = 0ul; j < s; ++j )
				{

					if ( scanBytes[ i + j ] != d[ j ] && d[ j ] != -1 )
					{
						found = false;
						break;
					}
				}
				if ( found ) { return reinterpret_cast< std::uintptr_t >( &scanBytes[ i ] ); }
			}
			return 0;
		}

		template <class T>
		inline T* scan_memory( T value )
		{
			auto rdataAddr = image_base + rdata_virtualaddress;

			for ( std::uint64_t addr = rdataAddr; addr < rdataAddr + rdata_size; addr += sizeof( T ) )
			{
				auto search = *reinterpret_cast< T* >( addr );
				if ( search == value )
					return ( T* ) addr;
			}

			return 0;
		}




		inline std::uint64_t current_peb( )
		{
			return __readgsqword( 0x60 );
		}

		inline std::uint64_t find_string( std::uint64_t base, std::string_view str ) {
			auto module_address = base;
			if ( !module_address )
				return 0;

			const auto dos_header = ( PIMAGE_DOS_HEADER ) module_address;
			const auto nt_headers = ( PIMAGE_NT_HEADERS ) ( ( std::uint8_t* ) module_address + dos_header->e_lfanew );
			const auto module_size = nt_headers->OptionalHeader.SizeOfImage;

			char* scanBytes = ( char* ) module_address;
			const std::size_t s = str.size( );
			for ( std::uint32_t i = 0; i < module_size - s; i++ ) {
				bool found = true;
				for ( std::uint32_t j = 0; j < s; j++ ) {
					if ( scanBytes[ i + j ] != str[ j ] ) {
						found = false;
						break;
					}
				}
				if ( found ) {
					return ( std::uint64_t ) &scanBytes[ i ];
				}
			}
			return 0;
		}

		inline std::uint64_t find_xref( std::uint64_t base, std::uint64_t addr, std::uint64_t startOff = 0 ) {
			auto module_address = base;
			if ( !module_address )
				return 0;

			const auto dos_header = ( PIMAGE_DOS_HEADER ) module_address;
			const auto nt_headers = ( PIMAGE_NT_HEADERS ) ( ( std::uint8_t* ) module_address + dos_header->e_lfanew );
			const auto module_size = nt_headers->OptionalHeader.SizeOfImage;

			std::uint64_t img = ( std::uint64_t ) module_address + startOff;
			for ( std::uint32_t i = 0; i < module_size - startOff; i++ ) {
				if ( img + i + sizeof( int ) + ( std::uint64_t ) * ( std::uint32_t* ) ( img + i ) == addr ) {
					return img + i + sizeof( int );
				}
			}
			return 0;
		}

	}


	namespace str
	{
		inline std::string format_str( const char* fmt, ... )
		{
			va_list args;
			va_start( args, fmt );

			const int size = _vscprintf( fmt, args ) + 1;
			std::vector<char> buffer( size );

			vsprintf_s( buffer.data( ), size, fmt, args );
			va_end( args );

			return std::string( buffer.data( ) );
		}

		inline void write_str( void* address, const char* string )
		{
			memcpy( address, string, strlen( string ) + 1 );
		}

		inline std::string parse_str( const std::string& jsonString, const std::string& key, size_t startPos = 0 )
		{
			std::string searchKey = "\"" + key + "\":\"";
			auto pos = jsonString.find( searchKey, startPos );
			if ( pos == std::string::npos )
			{
				return "";
			}
			pos += searchKey.length( );
			auto endPos = jsonString.find( "\"", pos );
			if ( endPos == std::string::npos )
			{
				return "";
			}
			startPos = endPos + 1;  // Update the starting position for the next search
			return jsonString.substr( pos, endPos - pos );
		}
	}

	namespace nt
	{
		typedef struct _UNICODE_STRING
		{
			unsigned short Length;
			unsigned short MaximumLength;
			wchar_t* Buffer;
		} UNICODE_STRING, * PUNICODE_STRING;

		typedef struct _PEB_LDR_DATA
		{
			unsigned char       Reserved1[ 8 ];
			void* Reserved2[ 3 ];
			LIST_ENTRY InMemoryOrderModuleList;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;

		typedef struct _PEB
		{
			unsigned char                          Reserved1[ 2 ];
			unsigned char                          BeingDebugged;
			unsigned char                          Reserved2[ 1 ];
			void* Reserved3[ 2 ];
			PPEB_LDR_DATA                 Ldr;
		} PEB, * PPEB;

		typedef struct _LIST_ENTRY
		{
			struct _LIST_ENTRY* Flink;
			struct _LIST_ENTRY* Blink;
		} LIST_ENTRY, * PLIST_ENTRY;

		typedef struct _LDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY InLoadOrderLinks;//0x0
			void* Reserved1[ 2 ];//0x10
			void* DllBase;//0x20
			void* EntryPoint;//0x28
			unsigned long SizeOfImage;//0x30
			UNICODE_STRING FullDllName;//0x34
			UNICODE_STRING BaseDllName;//0x44

		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		typedef struct _IMAGE_DOS_HEADER
		{      // DOS .EXE header
			unsigned short   e_magic;                     // Magic number
			unsigned short   e_cblp;                      // unsigned chars on last page of file
			unsigned short   e_cp;                        // Pages in file
			unsigned short   e_crlc;                      // Relocations
			unsigned short   e_cparhdr;                   // Size of header in paragraphs
			unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
			unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
			unsigned short   e_ss;                        // Initial (relative) SS value
			unsigned short   e_sp;                        // Initial SP value
			unsigned short   e_csum;                      // Checksum
			unsigned short   e_ip;                        // Initial IP value
			unsigned short   e_cs;                        // Initial (relative) CS value
			unsigned short   e_lfarlc;                    // File address of relocation table
			unsigned short   e_ovno;                      // Overlay number
			unsigned short   e_res[ 4 ];                    // Reserved unsigned shorts
			unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
			unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
			unsigned short   e_res2[ 10 ];                  // Reserved unsigned shorts
			long   e_lfanew;                    // File address of new exe header
		} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

		typedef struct _IMAGE_OPTIONAL_HEADER64
		{
			unsigned short                 Magic;
			unsigned char                 MajorLinkerVersion;
			unsigned char                 MinorLinkerVersion;
			unsigned long                SizeOfCode;
			unsigned long                SizeOfInitializedData;
			unsigned long                SizeOfUninitializedData;
			unsigned long                AddressOfEntryPoint;
			unsigned long                BaseOfCode;
			unsigned long long            ImageBase;
			unsigned long                SectionAlignment;
			unsigned long                FileAlignment;
			unsigned short                 MajorOperatingSystemVersion;
			unsigned short                 MinorOperatingSystemVersion;
			unsigned short                 MajorImageVersion;
			unsigned short                 MinorImageVersion;
			unsigned short                 MajorSubsystemVersion;
			unsigned short                 MinorSubsystemVersion;
			unsigned long                Win32VersionValue;
			unsigned long                SizeOfImage;
			unsigned long                SizeOfHeaders;
			unsigned long                CheckSum;
			unsigned short                 Subsystem;
			unsigned short                 DllCharacteristics;
			unsigned long long            SizeOfStackReserve;
			unsigned long long            SizeOfStackCommit;
			unsigned long long            SizeOfHeapReserve;
			unsigned long long            SizeOfHeapCommit;
			unsigned long                LoaderFlags;
			unsigned long                NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_FILE_HEADER
		{
			unsigned short  Machine;
			unsigned short  NumberOfSections;
			unsigned long TimeDateStamp;
			unsigned long PointerToSymbolTable;
			unsigned long NumberOfSymbols;
			unsigned short  SizeOfOptionalHeader;
			unsigned short  Characteristics;
		} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

		typedef struct _IMAGE_NT_HEADERS64
		{
			unsigned long Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER64 OptionalHeader;
		} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

		typedef struct _IMAGE_EXPORT_DIRECTORY
		{
			unsigned long   Characteristics;
			unsigned long   TimeDateStamp;
			unsigned short    MajorVersion;
			unsigned short    MinorVersion;
			unsigned long   Name;
			unsigned long   Base;
			unsigned long   NumberOfFunctions;
			unsigned long   NumberOfNames;
			unsigned long   AddressOfFunctions;     // RVA from base of image
			unsigned long   AddressOfNames;         // RVA from base of image
			unsigned long   AddressOfNameOrdinals;  // RVA from base of image
		} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

		typedef struct _IMAGE_DATA_DIRECTORY
		{
			unsigned long   VirtualAddress;
			unsigned long   Size;
		} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

		typedef struct _IMAGE_SECTION_HEADER
		{
			std::uint8_t Name[ 8 ]; // An 8-byte, null-padded UTF-8 string. If the string is exactly 8 characters long, there is no terminating null. For longer names, this is a pointer to a string in the string table.
			union
			{
				std::uint32_t PhysicalAddress;           // The physical address of the section, used when the section is loaded into memory.
				std::uint32_t VirtualSize;               // The actual size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded. This field is valid only if the section is non-empty.
			} Misc;
			std::uint32_t VirtualAddress;                // The address of the first byte of the section when loaded into memory, relative to the image base.
			std::uint32_t SizeOfRawData;                 // The size of the section (in bytes) or the size of the initialized data on disk.
			std::uint32_t PointerToRawData;              // A file pointer to the first page of the section within the COFF file.
			std::uint32_t PointerToRelocations;          // A file pointer to the beginning of the relocation entries for the section. This is set to zero for executable images or if there are no relocations.
			std::uint32_t PointerToLinenumbers;          // A file pointer to the beginning of the line-number entries for the section. This is set to zero if there are no line numbers.
			std::uint16_t  NumberOfRelocations;           // The number of relocation entries for the section. This is set to zero for executable images or if there are no relocations.
			std::uint16_t  NumberOfLinenumbers;           // The number of line-number entries for the section.
			std::uint32_t Characteristics;               // The flags that describe the characteristics of the section.
		} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;
	}

	namespace importer
	{
		inline auto get_exported_function( const std::uintptr_t module, const char* function ) -> void*
		{
			if ( !module )
				return 0;

			const auto dos_header = reinterpret_cast< nt::IMAGE_DOS_HEADER* >( module );
			const auto nt_header = reinterpret_cast< nt::IMAGE_NT_HEADERS64* >( module + dos_header->e_lfanew );

			const auto data_directory = reinterpret_cast< nt::IMAGE_DATA_DIRECTORY* >( &nt_header->OptionalHeader.DataDirectory[ 0 ] );
			const auto image_export_directory = reinterpret_cast< nt::IMAGE_EXPORT_DIRECTORY* >( module + data_directory->VirtualAddress );
			if ( !image_export_directory )
				return 0;

			const auto* const rva_table = reinterpret_cast< const unsigned long* >( module + image_export_directory->AddressOfFunctions );
			const auto* const export_table = reinterpret_cast< const unsigned long* >( module + image_export_directory->AddressOfNames );
			const auto* const ord_table = reinterpret_cast< const unsigned short* >( module + image_export_directory->AddressOfNameOrdinals );

			for ( unsigned int idx = 0; idx < image_export_directory->NumberOfNames; idx++ )
			{
				const auto fn_name = reinterpret_cast< const char* >( module + export_table[ idx ] );

				if ( !strcmp( fn_name, function ) )
					return reinterpret_cast< void* >( module + rva_table[ ord_table[ idx ] ] );
			}

			return 0;
		}

		inline std::uint64_t get_section_size( const uintptr_t module, const char* section )
		{
			const HMODULE GameModule = ( HMODULE ) module;
			const IMAGE_DOS_HEADER* DOSHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( GameModule );
			const IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< long long >( GameModule ) + DOSHeader->e_lfanew );
			auto size = NtHeaders->OptionalHeader.SizeOfImage;

			IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

			for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i )
			{
				if ( strcmp( reinterpret_cast< char* >( sectionHeader[ i ].Name ), section ) == 0 )
				{
					return ( std::uint64_t ) sectionHeader[ i ].Misc.VirtualSize;
				}
			}

			return 0;
		}

		inline std::uint64_t get_virtual_address( const uintptr_t module, const char* section )
		{
			const HMODULE GameModule = ( HMODULE ) module;
			const IMAGE_DOS_HEADER* DOSHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( GameModule );
			const IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< long long >( GameModule ) + DOSHeader->e_lfanew );
			auto size = NtHeaders->OptionalHeader.SizeOfImage;

			IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

			for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i )
			{
				if ( strcmp( reinterpret_cast< char* >( sectionHeader[ i ].Name ), section ) == 0 )
				{
					return ( std::uint64_t ) sectionHeader[ i ].VirtualAddress;
				}
			}

			return 0;
		}
	}
}

#endif
