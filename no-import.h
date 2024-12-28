#pragma once
#include <Windows.h>
#include <iostream>
#include <algorithm>
#include <chrono>
 
typedef struct PEB_LOADER_DATA
{
	UINT8 _PADDING_[ 12 ];
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;
 
typedef struct PEB_NEW
{
#ifdef _WIN64
	UINT8 _PADDING_[ 24 ];
#else
	UINT8 _PADDING_[ 12 ];
#endif
	PEB_LOADER_DATA* Ldr;
} PEB_NEW, * PPEB_NEW;
 
typedef struct _UNICODE_STRINGG
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRINGG;
 
typedef struct LOADER_TABLE_ENTRY
{
	LIST_ENTRY				InLoadOrderLinks;
	LIST_ENTRY				InMemoryOrderLinks;
	LIST_ENTRY				InInitializationOrderLinks;
	uintptr_t				DllBase;
	uintptr_t				EntryPoint;
	uint32_t				SizeOfImage;
	UNICODE_STRINGG			FullDllName;
	UNICODE_STRINGG			BaseDllName;
	uint8_t					FlagGroup[ 4 ];
	uint32_t				Flags;
	uint16_t				ObsoleteLoadCount;
	uint16_t				TlsIndex;
	LIST_ENTRY				HashLinks;
	uint32_t				TimeDateStamp;
	uintptr_t				EntryPointActivationContext;
	uintptr_t				Lock;
	uintptr_t				DdagNode;
	LIST_ENTRY				NodeModuleLink;
	uintptr_t				LoadContext;
	uintptr_t				ParentDllBase;
} LOADER_TABLE_ENTRY, * PLOADER_TABLE_ENTRY;
 
namespace Imp
{
	namespace Hash
	{
		enum Type_t : std::size_t
		{
			FNV_PRIME = 0x01000193,
			FNV_BASIS = 0x811C9DC5
		};
 
		inline constexpr int GetStringLength( const char* Str )
		{
			int Len = 0;
			while ( Str[ Len ] != '\0' )
			{
				Len++;
			}
 
			return Len;
		}
 
		inline constexpr std::size_t Hash( const char* Str )
		{
			int Len = GetStringLength( Str );
			std::size_t Ret = 0;
 
			for ( int i = 0; i < Len; i++ )
			{
				Ret = Ret ^ Str[ i ] * FNV_PRIME;
				Ret *= FNV_BASIS;
			}
 
			return Ret;
		}
 
		inline std::size_t Hash( std::string Str )
		{
			int Len = Str.length( );
			std::size_t Ret = 0;
 
			for ( int i = 0; i < Len; i++ )
			{
				Ret = Ret ^ Str[ i ] * FNV_PRIME;
				Ret *= FNV_BASIS;
			}
 
			return Ret;
		}
	}
 
	__forceinline void* XorAddress( void* Address )
	{
		std::uintptr_t Out = ( std::uintptr_t )Address;
 
		std::uintptr_t Keys[ 6 ];
		Keys[ 0 ] = sizeof( std::uintptr_t ) * 4096 * static_cast< int >( __DATE__[ 0 ] ) * static_cast< int >( __LINE__ ) * static_cast< int >( __TIMESTAMP__[ 0 ] );
		Keys[ 1 ] = sizeof( std::uintptr_t ) * 4096 * static_cast< int >( __DATE__[ 1 ] ) * static_cast< int >( __LINE__ ) * static_cast< int >( __TIMESTAMP__[ 1 ] );
		Keys[ 2 ] = sizeof( std::uintptr_t ) * 4096 * static_cast< int >( __DATE__[ 2 ] ) * static_cast< int >( __LINE__ ) * static_cast< int >( __TIMESTAMP__[ 2 ] );
		Keys[ 3 ] = sizeof( std::uintptr_t ) * 4096 * static_cast< int >( __DATE__[ 4 ] ) * static_cast< int >( __LINE__ ) * static_cast< int >( __TIMESTAMP__[ 11 ] );
		Keys[ 4 ] = sizeof( std::uintptr_t ) * 4096 * static_cast< int >( __DATE__[ 5 ] ) * static_cast< int >( __LINE__ ) * static_cast< int >( __TIMESTAMP__[ 12 ] );
		Keys[ 5 ] = sizeof( std::uintptr_t ) * 4096 * static_cast< int >( __DATE__[ 7 ] ) * static_cast< int >( __LINE__ ) * static_cast< int >( __TIMESTAMP__[ 14 ] );
 
		for ( int i = 0; i < sizeof( Keys ) / sizeof( std::uintptr_t ); i++ )
		{
			Out ^= Keys[ i ];
			if ( Out & 0x8000000000 )
			{
				Out &= ~( 0x8000000000 );
			}
			else
			{
				Out |= 0x8000000000;
			}
		}
 
		return ( void* )Out;
	}
 
	inline std::uintptr_t GetModule( std::size_t HashModule )
	{
		// Get PEB data.
#ifdef _WIN64
		static PEB_NEW* Peb = ( PEB_NEW* )__readgsqword( 0x60 );
#else
		static PEB_NEW* Peb = ( PEB_NEW* )__readfsdword( 0x30 );
#endif
		if ( !Peb )
			return 0;
 
		PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
		PLOADER_TABLE_ENTRY TableEntry = nullptr;
 
		// Iterate each module.
		while ( ListEntry != &Peb->Ldr->InLoadOrderModuleList && ListEntry )
		{
			// Declare table.
			TableEntry = CONTAINING_RECORD( ListEntry, LOADER_TABLE_ENTRY, InLoadOrderLinks );
 
			std::wstring wideNameString( TableEntry->BaseDllName.Buffer );
			std::string ModuleName( wideNameString.begin( ), wideNameString.end( ) );
 
			ModuleName.resize( ModuleName.length( ) - 4 );
 
			// Convert string to lowercase.
			std::transform( ModuleName.begin( ), ModuleName.end( ), ModuleName.begin( ), ::tolower );
 
			if ( Hash::Hash( ModuleName ) == HashModule )
				return ( std::uintptr_t )TableEntry->DllBase;
 
			// Update flink.
			ListEntry = ListEntry->Flink;
		}
 
		return 0;
	}
 
	inline std::uintptr_t GetExport( std::size_t ModuleHash, std::size_t FunctionHash )
	{
		unsigned char* Base = reinterpret_cast< unsigned char* >( GetModule( ModuleHash ) );
		PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Base;
 
		if ( Dos->e_magic == 0x5A4D )
		{
			PIMAGE_NT_HEADERS Nt = ( PIMAGE_NT_HEADERS )( Base + Dos->e_lfanew );
			if ( Nt->Signature )
			{
				IMAGE_EXPORT_DIRECTORY* ExportDirectory = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( Base + Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
				for ( int i = 0; i < ExportDirectory->NumberOfNames; i++ )
				{
					char* ExportName = reinterpret_cast< char* >( Base + reinterpret_cast< unsigned long* >( Base + ExportDirectory->AddressOfNames )[ i ] );
					if ( Hash::Hash( ExportName ) == FunctionHash )
					{
						unsigned short Ordinal = reinterpret_cast< unsigned short* >( Base + ExportDirectory->AddressOfNameOrdinals )[ i ];
						return reinterpret_cast< std::uintptr_t >( Base + reinterpret_cast< unsigned long* >( Base + ExportDirectory->AddressOfFunctions )[ Ordinal ] );
					}
				}
			}
		}
 
		return 0;
	}
}
 
#define HASH(x) \
[&]( ) \
{ \
	constexpr auto Out = Imp::Hash::Hash(x); \
	return Out; \
} ()
 
#define DEFINE_ENCRYPTED_IMPORT(mod, func) \
[&]( ) \
{ \
    return Imp::XorAddress( ( void* )Imp::GetExport( mod, func ) ); \
} ()
 
#define CALL_ENCRYPTED_IMPORT(addr, type, convention, ...) \
reinterpret_cast< type( convention )( ... ) >( Imp::XorAddress( addr ) ) ( __VA_ARGS__ ); \
 
#define CALL_ENCRYPTED_IMPORT(addr, type, convention, ...) \
[&]( ) \
{ \
    return reinterpret_cast< type( convention )( ... ) >( Imp::XorAddress( addr ) ) ( __VA_ARGS__ ); \
} ()
