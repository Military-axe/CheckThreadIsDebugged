#include <winternl.h>
#include <iostream>
#include "CurrentThreadStatus.h"
#include "util.h"

int main()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
        return 1;
    }

    if (!SetPrivilege(hToken, SE_DEBUG_NAME, true))
    {
        std::cerr << "Failed to enable SeDebugPrivilege." << std::endl;
        CloseHandle(hToken);
        return 1;
    }

    if (!CheckPrivilege(hToken, SE_DEBUG_NAME)) {
        std::cerr << "SeDebugPrivilege is not enabled." << std::endl;
        CloseHandle(hToken);
        return 1;
    }

    CurrentThreadStatus current_thread_status;

    while (true)
    {
        if (current_thread_status.IsHandleOpenedByExternalProcess())
        {
            std::cout << "Current thread is opened by external process." << std::endl;
        }
        else
        {
            std::cout << "Current thread is anti debug." << std::endl;
        }

        Sleep(5000);
    }
}