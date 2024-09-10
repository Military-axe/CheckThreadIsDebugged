#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <Psapi.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
const uint16_t SystemExtendedHandleInformation = 0x40;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    uint64_t object;
    uint64_t pid;
    uint64_t handle_value;
    uint32_t grant_access;
    uint16_t creator_back_trace_index;
    uint16_t object_type_index;
    uint32_t handle_attributes;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    uint64_t handle_count;
    uint64_t reversed;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef NTSTATUS(WINAPI *NtQueryInformationProcessPtr)(
    HANDLE ProcessHandle,
    uint32_t ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI *NtQuerySystemInformationPtr)(
    uint32_t SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

bool SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege);
bool CheckPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege);
NtQueryInformationProcessPtr GetNtQueryInformationProcess();
NtQuerySystemInformationPtr GetNtQuerySystemInformation();
bool GetProcessNameFromId(uint32_t processId, wchar_t *processName, uint32_t size);
uint32_t GetParentProcessId(uint32_t processId, NtQueryInformationProcessPtr NtQueryInformationProcess);
uint32_t GetTopLevelParentProcessId(uint32_t processId, NtQueryInformationProcessPtr NtQueryInformationProcess);