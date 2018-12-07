#include <cstdio>
#include <windows.h>
#include <winternl.h>
#include "os_structs.h"

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
	{ \
		EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
		EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
		EMIT(0xCB)                                   /*  retf                   */ \
	}

#define X64_End_with_CS(_cs) \
	{ \
		EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
		EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
		EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
		EMIT(0xCB)                                                                 /*  retf                         */ \
	}

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

//to fool M$ inline asm compiler I'm using 2 DWORDs instead of DWORD64
//use of DWORD64 will generate wrong 'pop word ptr[]' and it will break stack
union reg64
{
	DWORD dw[2];
	DWORD64 v;
};

WOW64::TEB64* getTEB64()
{
	reg64 reg;
	reg.v = 0;
	X64_Start();
	//R12 register should always contain pointer to TEB64 in WoW64 processes
	X64_Push(_R12);
	//below pop will pop QWORD from stack, as we're in x64 mode now
	__asm pop reg.dw[0]
	X64_End();
	//upper 32 bits should be always 0 in WoW64 processes
	if (reg.dw[1] != 0)
		return 0;
	return (WOW64::TEB64*)reg.dw[0];
}

DWORD getNTDLL64()
{
	static DWORD ntdll64 = 0;
	if (ntdll64 != 0)
		return ntdll64;

	WOW64::TEB64* teb64 = getTEB64();
	WOW64::PEB64* peb64 = teb64->ProcessEnvironmentBlock;
	WOW64::PEB_LDR_DATA64* ldr = peb64->Ldr;

	printf("TEB: %08X\n", (DWORD)teb64);
	printf("PEB: %08X\n", (DWORD)peb64);
	printf("LDR: %08X\n", (DWORD)ldr);

	printf("Loaded modules:\n");
	WOW64::LDR_DATA_TABLE_ENTRY64* head = (WOW64::LDR_DATA_TABLE_ENTRY64*)ldr->InLoadOrderModuleList.Flink;
	do
	{
		printf("  %ws\n", head->BaseDllName.Buffer);
		if (memcmp(head->BaseDllName.Buffer, L"ntdll.dll", head->BaseDllName.Length) == 0)
			ntdll64 = (DWORD)head->DllBase;
		head = (WOW64::LDR_DATA_TABLE_ENTRY64*)head->InLoadOrderLinks.Flink;
	}
	while (head != (WOW64::LDR_DATA_TABLE_ENTRY64*)&ldr->InLoadOrderModuleList);
	printf("NTDLL x64: %08X\n", ntdll64);
	return ntdll64;
}

DWORD getLdrGetProcedureAddress()
{
	BYTE* modBase = (BYTE*)getNTDLL64();
	IMAGE_NT_HEADERS64* inh = (IMAGE_NT_HEADERS64*)(modBase + ((IMAGE_DOS_HEADER*)modBase)->e_lfanew);
	IMAGE_DATA_DIRECTORY& idd = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (idd.VirtualAddress == 0)
		return 0;

	IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(modBase + idd.VirtualAddress);

	DWORD* rvaTable = (DWORD*)(modBase + ied->AddressOfFunctions);
	WORD* ordTable = (WORD*)(modBase + ied->AddressOfNameOrdinals);
	DWORD* nameTable = (DWORD*)(modBase + ied->AddressOfNames);
	//lazy search, there is no need to use binsearch for just one function
	for (DWORD i = 0; i < ied->NumberOfFunctions; i++)
	{
		if (strcmp((char*)modBase + nameTable[i], "LdrGetProcedureAddress"))
			continue;
		else
			return (DWORD)(modBase + rvaTable[ordTable[i]]);
	}
	return 0;
}

DWORD64 X64Call(DWORD func, int argC, ...)
{
	va_list args;
	va_start(args, argC);
	DWORD64 _rcx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _rdx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r8 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r9 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	reg64 _rax;
	_rax.v = 0;

	DWORD64 restArgs = (DWORD64)&va_arg(args, DWORD64);
	
	//conversion to QWORD for easier use in inline assembly
	DWORD64 _argC = argC;
	DWORD64 _func = func;

	DWORD back_esp = 0;

	__asm
	{
		;//keep original esp in back_esp variable
		mov    back_esp, esp
		
		;//align esp to 8, without aligned stack some syscalls may return errors !
		and    esp, 0xFFFFFFF8

		X64_Start();

		;//fill first four arguments
		push   _rcx
		X64_Pop(_RCX);
		push   _rdx
		X64_Pop(_RDX);
		push   _r8
		X64_Pop(_R8);
		push   _r9
		X64_Pop(_R9);
	
		push   edi

		push   restArgs
		X64_Pop(_RDI);

		push   _argC
		X64_Pop(_RAX);

		;//put rest of arguments on the stack
		test   eax, eax
		jz     _ls_e
		lea    edi, dword ptr [edi + 8*eax - 8]

		_ls:
		test   eax, eax
		jz     _ls_e
		push   dword ptr [edi]
		sub    edi, 8
		sub    eax, 1
		jmp    _ls
		_ls_e:

		;//create stack space for spilling registers
		sub    esp, 0x20

		call   _func

		;//cleanup stack
		push   _argC
		X64_Pop(_RCX);
		lea    esp, dword ptr [esp + 8*ecx + 0x20]

		pop    edi

		//set return value
		X64_Push(_RAX);
		pop    _rax.dw[0]

		X64_End();

		mov    esp, back_esp
	}
	return _rax.v;
}

DWORD64 GetProcAddress64(DWORD module, char* funcName)
{
	static DWORD _LdrGetProcedureAddress = 0;
	if (_LdrGetProcedureAddress == 0)
	{
		_LdrGetProcedureAddress = getLdrGetProcedureAddress();
		printf("LdrGetProcedureAddress: %08X\n", _LdrGetProcedureAddress);
		if (_LdrGetProcedureAddress == 0)
			return 0;
	}

	WOW64::ANSI_STRING64 fName = { 0 };
	fName.Buffer = funcName;
	fName.Length = strlen(funcName);
	fName.MaximumLength = fName.Length + 1;
	DWORD64 funcRet = 0;
	X64Call(_LdrGetProcedureAddress, 4, 
		(DWORD64)module, (DWORD64)&fName, 
		(DWORD64)0, (DWORD64)&funcRet);

	printf("%s: %08X\n", funcName, (DWORD)funcRet);
	return funcRet;
}

int wmain();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int argc = 0;
	int ret = 0;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
	if (argv)
	{
		ret = wmain();
		LocalFree(argv);
	}
	return ret;
}

int wmain()
{
	DWORD hNtdll = getNTDLL64();
	DWORD tmp = (DWORD)GetProcAddress64(hNtdll, "A_SHAInit");
	system("pause");
	return 0;
}
