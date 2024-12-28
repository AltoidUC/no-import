#include "no-import.h"
 
int main( )
{
    LoadLibraryA( "user32.dll" );
 
    static auto GetAsyncKeyStateAddr = DEFINE_ENCRYPTED_IMPORT( HASH( "user32" ), HASH( "GetAsyncKeyState" ) );
    while ( true )
    {
        if ( CALL_ENCRYPTED_IMPORT( GetAsyncKeyStateAddr, SHORT, __stdcall*, VK_F2 ) )
        {
            printf( "F2!\n" );
        }
 
        Sleep( 10 );
    }
 
    std::cin.get( );
    return 0;
}
