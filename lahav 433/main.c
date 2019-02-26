#include "ntdll_fun.h"

int SetPrivileges();
DWORD find_child(DWORD father_pid);
DWORD find_process_by_name(char *proc_name);
BOOLEAN DetachFromDebuggerProcess(DWORD pid);

int SetPrivileges() {
    TOKEN_PRIVILEGES priv = { 0 };
    HANDLE hToken = NULL;
    BOOL disableAllPrivilages = TRUE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME , &priv.Privileges[0].Luid)) {
            if (AdjustTokenPrivileges(hToken, !disableAllPrivilages, &priv, 0, NULL, NULL) == 0) {
                printf("AdjustTokenPrivilege Error! [%u]\n", GetLastError());
            }
        }

        if (LookupPrivilegeValue(NULL, SE_SYSTEMTIME_NAME, &priv.Privileges[0].Luid)) {
            if (AdjustTokenPrivileges(hToken, !disableAllPrivilages, &priv, 0, NULL, NULL) == 0) {
                printf("AdjustTokenPrivilege Error! [%u]\n", GetLastError());
            }
        }

        CloseHandle(hToken);
    }

    return GetLastError();
}

DWORD find_child(DWORD parent_pid) {
    wchar_t process_name[NAME_SIZE];
    HANDLE hProcessSnap;
    HANDLE hProcess;
    DWORD dwPriorityClass;
    PROCESSENTRY32 pe32;

    swprintf(process_name, NAME_SIZE, L"%hs", "run.exe");
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return -1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return -2;
    }

    do {
        if (!wcscmp(pe32.szExeFile, process_name) && pe32.th32ProcessID != parent_pid) {
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    MessageBoxA(0, "not found", "f*ck", 1);

    return -3;
}

DWORD find_process_by_name(char *proc_name) {
    wchar_t process_name[NAME_SIZE];
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;

    swprintf(process_name, NAME_SIZE, L"%hs", proc_name);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return -1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return -2;
    }

    do {
        if (!wcscmp(pe32.szExeFile, process_name)) {
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    MessageBoxA(0, "not found", "f*ck", 1);

    return FALSE;
}

BOOLEAN DetachFromDebuggerProcess(DWORD pid) 
{
    NTSTATUS status;
    HANDLE processHandle;
    HANDLE debugObjectHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HMODULE ntdllModule = GetModuleHandleA("ntdll");

    clientId.UniqueProcess = pid;
    clientId.UniqueThread = NULL;

    NtQueryInformationProcess pfnNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(ntdllModule, "NtQueryInformationProcess");
    NtSetInformationDebugObject pfnNtSetInformationDebugObject = (NtSetInformationDebugObject)GetProcAddress(ntdllModule, "NtSetInformationDebugObject");
    NtRemoveProcessDebug pfnNtRemoveProcessDebug = (NtRemoveProcessDebug)GetProcAddress(ntdllModule, "NtRemoveProcessDebug");
    NtOpenProcess pfnNtOpenProcess = (NtOpenProcess)GetProcAddress(ntdllModule, "NtOpenProcess");
    NtClose pfnNtClose = (NtClose)GetProcAddress(ntdllModule, "NtClose");

    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    if (NT_SUCCESS(status = pfnNtOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
        &objectAttributes,
        &clientId
    )))
    {
        status = pfnNtQueryInformationProcess(processHandle, 0x1E, &debugObjectHandle, sizeof(DWORD), NULL);
        if (NT_SUCCESS(status))
        {
            /*ULONG killProcessOnExit;

            // Disable kill-on-close.
            killProcessOnExit = 0;

            pfnNtSetInformationDebugObject(
                debugObjectHandle,
                0x1,
                &killProcessOnExit,
                sizeof(ULONG),
                NULL
            );*/

            status = pfnNtRemoveProcessDebug(processHandle, debugObjectHandle);

            pfnNtClose(debugObjectHandle);
        }

        pfnNtClose(processHandle);
    }

    if (status == 0xC0000353) // STATUS_PORT_NOT_SET
    {
        return FALSE;
    }

    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    return TRUE;
}

int main()
{
    STARTUPINFO si;
    SYSTEMTIME st;
    HANDLE hProcess_cmd, hProcess_child;
    DEBUG_EVENT my_child_ev;
    PROCESS_INFORMATION pi;
    DWORD child_pid, cmd_pid;
    BOOL detached, process_exit;
    BOOL inheritHandle = TRUE;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    st.wYear = 2032;
    st.wMonth = 1;
    st.wDayOfWeek = 1;
    st.wDay = 1;
    st.wHour = 1;
    st.wMinute = 1;
    st.wSecond = 1;
    st.wMilliseconds = 1;

    SetPrivileges(); // 1. get privileges to change systemtime
    if (!SetSystemTime(&st)) { // 1.1 change systemtime -> year = 2032
        printf("[-]SetSystemTime failed (%d).\n", GetLastError());
    }

    // 2. run "run.exe"
    if (!CreateProcessA("run.exe", NULL, NULL, NULL, !inheritHandle, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        printf("[-]CreateProcess failed (%d).\n", GetLastError());
        return;
    }

    printf("[+]CreateProcess Successfuly, the parent pid is %d\n", pi.dwProcessId);
    Sleep(5000);  // letting the parent unpack and run the child
    child_pid = find_child(pi.dwProcessId);

    if (child_pid >= 0) {

        // 3. detach child process from parent deubgger
        detached = DetachFromDebuggerProcess(child_pid);
        if (!detached)
        {
            printf("[+]Failed to deattach the parent debugger\n");
            return;
        }

        printf("[+]Successfuly Deattach Debugger\n");

        cmd_pid = find_process_by_name("cmd.exe");  /// might fail if you have an unrelated cmd open
        if (child_pid >= 0)
        {
            hProcess_cmd = OpenProcess(PROCESS_TERMINATE, !inheritHandle, cmd_pid);

            if (hProcess_cmd) {
                // 4. kill cmd.exe and run.exe (kill two birds with one stone)
                if (TerminateProcess(hProcess_cmd, 0)) {
                    printf("[+]Successfuly kill cmd.exe and run.exe (parent)\n");
                }
                else
                {
                    printf("[-]Failed to kill cmd.exe and run.exe (parent)\n");
                    return;
                }

                hProcess_child = OpenProcess(PROCESS_ALL_ACCESS, !inheritHandle, child_pid); // maybe not needed..
                DebugActiveProcess(child_pid); // 5. now we can attach our debugger to child process

                process_exit = FALSE;
                while (!process_exit)
                {

                    WaitForDebugEvent(&my_child_ev, INFINITE);

                    switch (my_child_ev.dwDebugEventCode) {

                    case EXIT_PROCESS_DEBUG_EVENT:
                        process_exit = TRUE;
                        break;

                    default:
                        ContinueDebugEvent(my_child_ev.dwProcessId, my_child_ev.dwThreadId, DBG_CONTINUE); // first event is CREATE_PROCESS_DEBUG_EVENT
                    }
                }
                DetachFromDebuggerProcess(child_pid);

            }

        }

    }
}
