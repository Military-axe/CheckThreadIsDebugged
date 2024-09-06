#include <winternl.h>
#include <iostream>
#include "CurrentThreadStatus.h"
#include "util.h"

int main()
{
    bool status = EnablePrivileges();
    if (status == false)
    {
        std::cout << "set privilege value failed; error: " << GetLastError() << std::endl;
        return -1;
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