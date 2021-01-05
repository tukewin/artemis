/*************************************************************************



				$ artemis $
 				shoutout, credits: 919team, orak, artom<3, checkpoint
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
 
// bitmask values for CodeIntegrityOptions
#define CODEINTEGRITY_OPTION_ENABLED                        0x01
#define CODEINTEGRITY_OPTION_TESTSIGN                       0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED                   0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED         0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED    0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD                     0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD            0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED              0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD                   0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED              0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED              0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED    0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED   0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED               0x2000

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

namespace typedefs
{
	using NtQuerySystemInformationTypedef = NTSTATUS(*)( ULONG, PVOID, ULONG, PULONG );

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
	{
		ULONG   Length;
		ULONG   CodeIntegrityOptions;
	} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45,
		SystemCodeIntegrityInformation = 103,
		SystemPolicyInformation = 134,
	} SYSTEM_INFORMATION_CLASS;
}

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
	bool IsDebuggerPresentPatched();
	bool NtQuerySystemInfoCheck();
	bool TitanHide();
public:
	void Start();
};

extern CArtemis artem;