#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NAME_SIZE 10

#define InitializeObjectAttributes(p, n, a, r, s) { \
     (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
     (p)->RootDirectory = r; \
     (p)->Attributes = a; \
     (p)->ObjectName = n; \
     (p)->SecurityDescriptor = s; \
     (p)->SecurityQualityOfService = NULL; \
       }

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef LONG(NTAPI *NtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength);

typedef LONG(NTAPI *NtSetInformationDebugObject)(
    _In_ HANDLE DebugObjectHandle,
    _In_ DWORD     DebugObjectInformationClass,
    _In_ PVOID     DebugInformation,
    _In_ ULONG     DebugInformationLength,
    _Out_opt_ PULONG     ReturnLength);

typedef LONG(NTAPI *NtRemoveProcessDebug)(
    _In_ HANDLE     ProcessHandle,
    _In_ HANDLE     DebugObjectHandle);

typedef LONG(NTAPI *NtOpenProcess)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          AccessMask,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PCLIENT_ID           ClientId);

typedef LONG(NTAPI *NtClose)(
    IN HANDLE Handle);
