#include <Windows.h>
#include <winternl.h>
#include "util.h"

/// @brief 动态从ntdll.dll模块种获取NtQuerySystemInformation函数地址
/// @return 如果获取成功返回指向NtQuerySystemInformation函数的指针，如果获取失败则返回nullptr
NtQuerySystemInformationPtr GetNtQuerySystemInformation()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
    {
        std::cerr << "Failed to load ntdll.dll" << std::endl;
        return nullptr;
    }

    NtQuerySystemInformationPtr NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationPtr>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
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
        // std::cerr << "open process " << processId << " failed; error: " << GetLastError() << std::endl;
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

    NtQueryInformationProcessPtr NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessPtr>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess)
    {
        std::cerr << "Failed to get NtQueryInformationProcess address" << std::endl;
        FreeLibrary(hNtdll);
        return nullptr;
    }

    return NtQueryInformationProcess;
}

/// @brief 传入子进程id，查询进程的父进程ID
/// @param processId 子进程id
/// @param NtQueryInformationProcess，NtQueryInformationProcess函数指针
/// @return 如果查询成功返回父进程ID，如果查询失败返回0
uint32_t GetParentProcessId(uint32_t processId, NtQueryInformationProcessPtr NtQueryInformationProcess)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess)
    {
        // std::cerr << "Failed to open process with ID: " << processId  << "; error: " << GetLastError() << std::endl;
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

/// @brief 传入子进程id，获取对应的最顶级的父进程ID；需要调试权限令牌
/// @param processId 子进程id
/// @return 如果获取失败，返回原本进程ID；成功返回父进程id
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

    return currentProcessId;
}

bool SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        return FALSE;
    }

    return TRUE;
}

bool CheckPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege)
{
    PRIVILEGE_SET privs;
    LUID luid;
    BOOL bResult = FALSE;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
        return FALSE;
    }

    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!PrivilegeCheck(hToken, &privs, &bResult))
    {
        std::cerr << "PrivilegeCheck error: " << GetLastError() << std::endl;
        return FALSE;
    }

    return bResult;
}
