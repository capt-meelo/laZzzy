#pragma once
#include "struct.h"

int wprintf(
	const wchar_t* format,
	...
);

int StrCmpW(
	IN PCWSTR psz1,
	IN PCWSTR psz2
);

// ntdll.dll
NTSTATUS NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
);

NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
);

NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
);

NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL
);

NTSTATUS NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL
);

NTSTATUS NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL
);

NTSTATUS NtMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Win32Protect,
	IN PEXT_PARAMS ExtParameters OPTIONAL,
	IN ULONG ExtParametersCount
);

NTSTATUS NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress
);

NTSTATUS NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL
);

NTSTATUS NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext
);

NTSTATUS NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context
);

NTSTATUS NtClose(
	IN HANDLE Handle
);

NTSTATUS NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

NTSTATUS NtQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime
);

NTSTATUS NtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval
);

NTSTATUS RtlFlsAlloc(
	PFLS_CALLBACK_FUNCTION callback,
	ULONG* index
);

NTSTATUS RtlFlsSetValue(
	ULONG index,
	void* data
);

NTSTATUS RtlFlsFree(
	ULONG index
);

PVOID RtlAllocateHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags OPTIONAL,
	IN SIZE_T Size
);


// win32u.dll
HWND NtUserFindWindowEx(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType
);

DWORD NtUserQueryWindow(
	HWND hWnd,
	DWORD Index
);

BOOL NtUserMessageCall(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam,
	ULONG_PTR ResultInfo,
	DWORD dwType, // FNID_XX types
	BOOL Ansi
);

UINT_PTR NtUserSetTimer(
	IN HWND hWnd,
	IN UINT_PTR nIDEvent,
	IN UINT uElapse,
	IN TIMERPROC lpTimerFunc
);

BOOL NtUserGetMessage(
	IN PMSG pMsg,
	IN HWND hWnd,
	IN UINT MsgFilterMin,
	OUT UINT MsgFilterMax
);

LRESULT NtUserDispatchMessage(
	PMSG pMsg
);

BOOL NtUserOpenClipboard(
	IN HWND hWndNewOwner,
	OUT PBOOL pfEmptyClient
);

NTSTATUS NtUserSetClipboardData(
	IN UINT fmt,
	IN HANDLE hData,
	set_clipboard_params* params
	//IN PSETCLIPBDATA pUnsafeScd
);

BOOL NtUserCloseClipboard(
	VOID
);
