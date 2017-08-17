    typedef enum  {
		NameUnknown           = 0,
		NameFullyQualifiedDN  = 1,
		NameSamCompatible     = 2,
		NameDisplay           = 3,
		NameUniqueId          = 6,
		NameCanonical         = 7,
		NameUserPrincipal     = 8,
		NameCanonicalEx       = 9,
		NameServicePrincipal  = 10,
		NameDnsDomain         = 12
    } EXTENDED_NAME_FORMAT, *PEXTENDED_NAME_FORMAT;

    CHAR *username = NULL;
    CHAR *pSlash = NULL;
    DWORD dwSize = 256;
    BOOLEAN WINAPI(*GetUserNameEx)(EXTENDED_NAME_FORMAT, LPTSTR, PULONG);
    GetUserNameEx = GetProcAddress(LoadLibrary("Secur32.dll"), "GetUserNameExA");

    if(GetUserNameEx == NULL) {
        ExitProcess(0);
    }

    username = (CHAR*)GlobalAlloc(GPTR, dwSize);
    GetUserNameEx(NameSamCompatible, username, &dwSize);

    pSlash = strstr(username, "\\");
    username[pSlash - username] = 0x00;

    if(strcmp(username, "[DOMAIN]") != 0) {
        ExitProcess(0);
    }
    GlobalFree(username);
