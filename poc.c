#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    DWORD processID = 0;

    if (argc == 2)
    {
        processID = atoi(argv[1]);
    }
    else
    {
        printf("Please specify a process ID.\n");
        return 0;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

    if (hProcess == NULL)
    {
        printf("Could not open process with ID %d.\n", processID);
        return 0;
    }

    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    LPVOID remoteString = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen("Psapi.dll") + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, remoteString, "Psapi.dll", strlen("Psapi.dll") + 1, NULL);

    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, remoteString, 0, NULL);

    WaitForSingleObject(hProcess, INFINITE);

    VirtualFreeEx(hProcess, remoteString, strlen("Psapi.dll") + 1, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
