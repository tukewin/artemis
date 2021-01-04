#pragma once
#include "Artemis.h"

CArtemis::CArtemis()
{
}

CArtemis::~CArtemis()
{
}

void CArtemis::Start()
{
	std::thread traverse(&IsMemoryTraversed, this);
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
	Whenever a memory is traversed, it gets added into the working set
	Put this in a standalone thread for best results
*/
bool CArtemis::IsMemoryTraversed()
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

