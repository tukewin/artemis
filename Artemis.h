/*************************************************************************



				$ artemis $
				developed by: worldgonemad
				shoutout, credits: checkpoint
				credits for the working set idea: penguon
				shoutout all my guwop brothers



**************************************************************************/


#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <thread>

#pragma pack(push, 1)
struct DbgUiRemoteBreakinPatch
{
	WORD  push_0;
	BYTE  push;
	DWORD CurrentPorcessHandle;
	BYTE  mov_eax;
	DWORD TerminateProcess;
	WORD  call_eax;
};
#pragma pack(pop)

/*
Artemis: a Greek goddess who protected young women until they marry.
*/

class CArtemis
{
public:
	CArtemis();
	~CArtemis();
private:
	std::vector<PVOID> fnList;
private:
	void AntiAttach();
	void PatchRemoteBreakin();
	bool CheckHardwareBP();
	bool FoundBP(BYTE cByte, std::vector<PVOID> pMemory, SIZE_T nMemorySize);
	bool Watchover();
	bool IsMemoryTraversed();
	bool IsDebuggerPresentPatched();
public:
	void Start();
};

extern CArtemis artem;