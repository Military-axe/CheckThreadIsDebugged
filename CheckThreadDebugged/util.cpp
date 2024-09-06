#include <Windows.h>
#include <winternl.h>
#include "util.h"

/// @brief 动态从ntdll.dll模块种获取NtQuerySystemInformation函数地址
/// @return 如果获取成功返回指向NtQuerySystemInformation函数的指针，如果获取失败则返回nullptr
NtQuerySystemInformationPtr GetNtQuerySystemInformationPtr()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
    {
        std::cerr << "Failed to load ntdll.dll" << std::endl;
        return nullptr;
    }

    NtQuerySystemInformationPtr NtQuerySystemInformation = (NtQuerySystemInformationPtr)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
    {
        std::cerr << "Failed to load NtQuerySystemInformation" << std::endl;
        FreeLibrary(hNtdll);
        return nullptr;
    }

    return NtQuerySystemInformation;
}

/// @brief 获取进程id对应的进程名称
/// @param processId 需要查询的进程id
/// @param processName 对应的结果进程名称，结果返回在processName中
/// @param size processName缓冲区大小
/// @return 如果获取成功则返回true，否则返回false
bool GetProcessNameFromId(uint32_t processId, wchar_t *processName, uint32_t size)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
    if (hProcess == nullptr)
    {
        return false;
    }

    uint32_t len = GetModuleFileNameExW(hProcess, nullptr, processName, size);
    if (len == 0)
    {
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

/// @brief 获取 NtQueryInformationProcess 函数指针
/// @return 返回NtQueryInformationProcess 函数指针
NtQueryInformationProcessPtr GetNtQueryInformationProcess()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
    {
        std::cerr << "Failed to load ntdll.dll" << std::endl;
        return nullptr;
    }

    NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess)
    {
        std::cerr << "Failed to get NtQueryInformationProcess address" << std::endl;
        FreeLibrary(hNtdll);
        return nullptr;
    }

    return NtQueryInformationProcess;
}

/// @brief 传入子进程id查询进程的父进程ID
/// @param processId
/// @param NtQueryInformationProcess
/// @return
uint32_t GetParentProcessId(uint32_t processId, NtQueryInformationProcessPtr NtQueryInformationProcess)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess)
    {
        std::cerr << "Failed to open process with ID: " << processId << std::endl;
        return 0;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    CloseHandle(hProcess);

    if (status != 0)
    {
        std::cerr << "NtQueryInformationProcess failed with status: " << status << std::endl;
        return 0;
    }

    return static_cast<uint32_t>(pbi.UniqueProcessId);
}

/// @brief 传入子进程id，获取对应的最顶级的父进程ID
/// @param processId 子进程id
/// @return 如果获取失败，返回0；成功返回父进程id
uint32_t GetTopLevelParentProcessId(uint32_t processId, NtQueryInformationProcessPtr NtQueryInformationProcess)
{
    uint32_t currentProcessId = processId;
    uint32_t parentProcessId = 0;

    while (true)
    {
        uint32_t newParentProcessId = GetParentProcessId(currentProcessId, NtQueryInformationProcess);
        if (newParentProcessId == 0 || newParentProcessId == currentProcessId)
        {
            break;
        }
        parentProcessId = newParentProcessId;
        currentProcessId = newParentProcessId;
    }

    return parentProcessId;
}
