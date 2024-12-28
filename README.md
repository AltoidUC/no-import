### no-import
Obfuscate WinAPI calls to make them more difficult to decipher. Note this does not spoof the call / return address, but makes it more difficult to reverse engineer and determine what the function is.

### Example Usage
```cpp
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
```

### Pseudo-code
Below is the produced pseudo-code from the main.cpp file.
```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdi
  __int64 v4; // rcx
  _DWORD *v5; // rbp
  unsigned int v6; // ebx
  unsigned int v7; // esi
  unsigned int *v8; // r11
  _BYTE *v9; // r9
  int v10; // ecx
  _BYTE *v11; // rax
  __int64 v12; // r8
  __int64 v13; // rdx
  __int64 v14; // r8
  unsigned int v15; // r9d
  __int64 *v16; // r10
  __int64 v17; // rdx
  unsigned __int64 v18; // rax
  __int64 v19; // r8
  __int64 *v20; // r9
  unsigned __int64 v21; // rdx
  __int64 v22; // rcx
  __int64 v23; // rdx
  __int64 v25; // [rsp+20h] [rbp-58h] BYREF
  __int64 v26; // [rsp+28h] [rbp-50h]
  __int64 v27; // [rsp+30h] [rbp-48h]
  __int64 v28; // [rsp+38h] [rbp-40h]
  __int64 v29; // [rsp+40h] [rbp-38h]
  __int64 v30; // [rsp+48h] [rbp-30h]
 
  LoadLibraryA("user32.dll");
  if ( dword_14000672C > *(*NtCurrentTeb()->ThreadLocalStoragePointer + 4i64) )
  {
    Init_thread_header(&dword_14000672C, 4i64, 0x4C79A0000i64, 0x85F180000i64);
    if ( dword_14000672C == -1 )
    {
      v3 = sub_140001230(0x5F8C20C38C51C41Ci64);
      if ( *v3 == 23117 && (v4 = *(v3 + 60), *(v4 + v3)) && (v5 = (v3 + *(v4 + v3 + 136)), v6 = 0, (v7 = v5[6]) != 0) )
      {
        v8 = (v3 + v5[8]);
        while ( 1 )
        {
          v9 = (v3 + *v8);
          v10 = 0;
          if ( *v9 )
          {
            v11 = (v3 + *v8);
            do
            {
              ++v10;
              ++v11;
            }
            while ( *v11 );
          }
          v12 = 0i64;
          v13 = 0i64;
          if ( v10 > 0 )
          {
            do
              v12 = 2166136261u * ((16777619i64 * v9[v13++]) ^ v12);
            while ( v13 < v10 );
            if ( v12 == 0xDF249D441DB2EE24ui64 )
              break;
          }
          ++v6;
          ++v8;
          if ( v6 >= v7 )
            goto LABEL_14;
        }
        v14 = v3 + *(v3 + v5[7] + 4i64 * *(v3 + v5[9] + 2i64 * v6));
      }
      else
      {
LABEL_14:
        v14 = 0i64;
      }
      v25 = 0x4C79A0000i64;
      v26 = 0x85F180000i64;
      v27 = 0x9E68E0000i64;
      v28 = 0x221820000i64;
      v29 = 0x29AA40000i64;
      v30 = 0x241BC0000i64;
      v15 = 0;
      v16 = &v25;
      do
      {
        v17 = *v16 ^ v14;
        v14 = v17 & 0xFFFFFF7FFFFFFFFFui64;
        if ( (v17 & 0x8000000000i64) == 0 )
          v14 = v17 | 0x8000000000i64;
        ++v15;
        ++v16;
      }
      while ( v15 < 6 );
      qword_140006740 = v14;
      Init_thread_footer(&dword_14000672C);
    }
  }
  while ( 1 )
  {
    v18 = qword_140006740;
    v25 = 0x4C79A0000i64;
    v26 = 0x85F180000i64;
    v27 = 0x9E68E0000i64;
    v28 = 0x221820000i64;
    v29 = 0x29AA40000i64;
    v30 = 0x241BC0000i64;
    LODWORD(v19) = 0;
    v20 = &v25;
    do
    {
      v21 = *v20 ^ v18;
      v22 = v21 | 0x8000000000i64;
      v18 = v21 & 0xFFFFFF7FFFFFFFFFui64;
      v23 = v21 & 0x8000000000i64;
      if ( !v23 )
        v18 = v22;
      v19 = (v19 + 1);
      ++v20;
    }
    while ( v19 < 6 );
    if ( (v18)(113i64, v23, v19, v20, v25, v26, v27, v28, v29, v30) )
      sub_140001010("F2!\n");
    Sleep(0xAu);
  }
}
```
