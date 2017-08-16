    HANDLE hSnap = NULL;
    PROCESSENTRY32 pe32;
    BOOL bFound = FALSE;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) {
        ExitProcess(0);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(!Process32First(hSnap, &pe32)) {
        ExitProcess(0);
    }

    do {
        if(strcmp(pe32.szExeFile, "[PROCESS]") == 0) {
            bFound = TRUE;
            break;
        }
    } while (Process32Next(hSnap, &pe32));

    CloseHandle(hSnap);

    if(!bFound) {
        ExitProcess(0);
    }
