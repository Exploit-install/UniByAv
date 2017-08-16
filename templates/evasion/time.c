    DWORD dwTick;
    DWORD dwTimer = [TIME];
    dwTick = GetTickCount();
    SleepEx(dwTimer, FALSE);
    dwTick = GetTickCount() - dwTick;

    if(!(dwTick >= dwTimer && dwTick < dwTimer + 200)) {
        ExitProcess(0);
    }
