#pragma once
#include "Artemis.h"

/*
	Whenever a memory is traversed, it gets added into the working set
	Put this in a standalone thread for best results
*/
bool IsMemoryTraversed()
{
	auto m = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	PSAPI_WORKING_SET_EX_INFORMATION _set;
	_set.VirtualAddress = m;

	while (true)
		if (QueryWorkingSetEx(GetCurrentProcess(), &_set, sizeof(_set)) && ( _set.VirtualAttributes.Valid & 0x1 ))
		{
			for (long long int i = 0; ++i; ( &i )[ i ] = i);
			*( ( char * ) NULL ) = 0;
		}
}

CArtemis::CArtemis()
{
}

CArtemis::~CArtemis()
{
}

void CArtemis::Start()
{
	std::thread traverse(&IsMemoryTraversed);
	traverse.detach();

	while (true) {
		/*
			List of functions to search for breakpoints
		*/
		fnList.push_back(&MessageBoxA);
		fnList.push_back(&GetProcAddress);
		fnList.push_back(&VirtualProtect);

		this->AntiAttach();

		if (this->IsDebuggerPresentPatched())
		{
			for (long long int i = 0; ++i; ( &i )[ i ] = i); // essentially just a way to crash the program
			*( ( char * ) NULL ) = 0;
		}
		this->PatchRemoteBreakin();
		this->Watchover();

		if (this->TitanHide()) {
			MessageBoxA(0, "The program can not be run with test-signing on. Please disable it and try again.", 0, 0);
			for (long long int i = 0; ++i; ( &i )[ i ] = i);
		}

		if (this->NtQuerySystemInfoCheck())
		{
			/* If this is hooked, we can suppose that its an Anti-Anti-Debug measure,
				yet we cannot rely just on this, an ideal solution would be to unhook
				critical DLLs such as `kernel32.dll`, `ntdll.dll`, `user32.dll` or similar */
		}
	}
}

/*
	kernel32!IsDebuggerPresent()
	A popular way to detect a debugger is to call kernel32!IsDebuggerPresent()
	Instead of examining the process memory for breakpoints, we can verify if kernel32!IsDebuggerPresent() was modified.
	Even with enabled ASLR, Windows libraries are loaded to the same base addresses in all the processes.
*/
bool CArtemis::IsDebuggerPresentPatched()
{
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return false;

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
	if (!pIsDebuggerPresent)
		return false;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
		return false;

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
		return false;

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				continue;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				continue;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				continue;

			if (dwFuncBytes != *( PDWORD ) pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				break;
			}
		}
		__finally
		{
			if (hProcess)
				CloseHandle(hProcess);
			else
			{

			}
		}
	} while (Process32NextW(hSnapshot, &ProcessEntry));

	if (hSnapshot)
		CloseHandle(hSnapshot);

	return bDebuggerPresent;
}

/*
	ntdll!DbgBreakPoint()
	- is called when a debugger attaches to a running process.
	- allows the debugger to gain control because an exception is raised which it can intercept
	- erasing the breakpoint will result in the debugger not breaking in and exiting the thread
*/
void CArtemis::AntiAttach()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*( PBYTE ) pDbgBreakPoint = ( BYTE ) 0xC3; // 0xC3 == RET
}

/*
	ntdll!DbgUiRemoteBreakin()
	When a debugger calls the kernel32!DebugActiveProcess(), a debugger calls ntdll!DbgUiRemoteBreakin() correspondingly.
	To prevent the debugger from attaching to the process, we can patch ntdll!DbgUiRemoteBreakin() code to invoke the kernel32!TerminateProcess().
*/
void CArtemis::PatchRemoteBreakin()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
	if (!pDbgUiRemoteBreakin)
		return;

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return;

	FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
	if (!pTerminateProcess)
		return;

	DbgUiRemoteBreakinPatch patch = { 0 };
	patch.push_0 = '\x6A\x00';
	patch.push = '\x68';
	patch.CurrentPorcessHandle = 0xFFFFFFFF;
	patch.mov_eax = '\xB8';
	patch.TerminateProcess = ( DWORD ) pTerminateProcess;
	patch.call_eax = '\xFF\xD0';

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
		return;

	::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
			   &patch, sizeof(DbgUiRemoteBreakinPatch));
	VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}

/*
	Debug registers DR0, DR1, DR2 and DR3 can be retrieved from the thread context.
	If they contain non-zero values, it may mean that a hardware breakpoint was set.
*/
bool CArtemis::CheckHardwareBP()
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ctx))
		return false;

	return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

/*
	Search the first MemorySize of bytes for an INT3 instruction
*/
bool CArtemis::FoundBP(BYTE Byte, std::vector<PVOID> Memory, SIZE_T MemorySize = 0)
{
	for (PVOID function : this->fnList) {
		PBYTE pBytes = ( PBYTE ) function;
		for (SIZE_T i = 0; i <= SIZE_T(function); i++)
		{
			if (( ( MemorySize > 0 ) && ( i >= MemorySize ) ) ||
				( ( MemorySize == 0 ) && ( pBytes[ i ] == 0xC3 ) ))
				break;

			if (pBytes[ i ] == Byte)
				return true;
		}
		return false;
	}
}

/*
	Traverses the function in the CArtemis!fnList for the 0xCC (int3) instructions
*/
bool CArtemis::Watchover()
{
	if (this->FoundBP(0xCC, fnList))
	{
		for (long long int i = 0; ++i; ( &i )[ i ] = i);
		*( ( char * ) NULL ) = 0;
	}

	return false;
}

/*
	Plugins like ScyllaHide, SharpOD do tend to hook NtQuerySystemInformation
	in order to circumvent the detection of a debugger by placing a hook on
	the first instruction. This can be revealed by checking whether the 1st
	opcode is equal to an 'invalid' (for ex. jmp) instruction.

	For extra validation, I'd recommend restoring the original bytes on critical
	functions like this.

	[!] This might trigger a false positive since apart from ScyllaHide, certain
	anti-virus programs tend to hook this (ex. Kaspersky).
*/
bool CArtemis::NtQuerySystemInfoCheck()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	if (!hNtdll) // If this fails, somebody tried to prevent ntdll from loading &or has their Windows seriously corrupted.
		return true;

	FARPROC _instr = GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (*( BYTE * ) _instr == 0xE9 || *( BYTE * ) _instr == 0x90 || *( BYTE * ) _instr == 0xC3)
	{
		return true;
	}

	return false;
}

/*
	TitanHide is a driver intended to hide debuggers from certain processes.
	The driver hooks various Nt* kernel functions (using SSDT table hooks) and modifies the return values of the original functions.
	https://github.com/mrexodia/TitanHide

	While the driver does a very good job of hiding a debugger, it requires test signing to be enabled to work.
	While sure, Patchguard CAN be disabled, most people will not bother and will just enable test-signing.

	[!] This might trigger a false positive as some people have their test-signing enabled on accident, a simple warning
	should be enough.
*/
bool CArtemis::TitanHide()
{
	const auto module = GetModuleHandleW(L"ntdll.dll");

	const auto information = reinterpret_cast< typedefs::NtQuerySystemInformationTypedef >( GetProcAddress(
		module, "NtQuerySystemInformation") );

	typedefs::SYSTEM_CODEINTEGRITY_INFORMATION sci;

	sci.Length = sizeof sci;

	information(typedefs::SystemCodeIntegrityInformation, &sci, sizeof sci, nullptr);

	const auto ret = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || sci.CodeIntegrityOptions &
		CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

	if (ret != 0)
		return true;
	else
		return false;
}

