#include <ntifs.h>
#include "AllocateMemory.h"
#define PTE_BASE 0xFFFFF68000000000L
#define PDE_BASE 0xFFFFF6FB40000000L
#define PXE_BASE 0xFFFFF6FB7DA00000L
#define PML_BASE 0xFFFFF6FB7DBED000L

typedef struct HardwarePteX64 {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]
	ULONG64 cache_disable : 1;       //!< [4]
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 36;  //!< [12:47]
	ULONG64 reserved1 : 4;           //!< [48:51]
	ULONG64 software_ws_index : 11;  //!< [52:62]
	ULONG64 no_execute : 1;          //!< [63]
}HardwarePte;

PVOID GetPteBase()
{
	static ULONG64 BaseAddr = NULL;
	if (BaseAddr) return BaseAddr;
	UNICODE_STRING uName = { 0 };
	RtlInitUnicodeString(&uName, L"MmGetVirtualForPhysical");
	ULONG64 func = MmGetSystemRoutineAddress(&uName);
	BaseAddr = *(PUINT64)(func + 0x22);
	return BaseAddr;
}




ULONG64 GetMmPfnDataBase()
{
	static ULONG64 BaseAddr = NULL;
	if (BaseAddr) return BaseAddr;
	UNICODE_STRING uName = { 0 };
	RtlInitUnicodeString(&uName, L"MmGetVirtualForPhysical");
	ULONG64 func = MmGetSystemRoutineAddress(&uName);
	BaseAddr = (*(PUINT64)(func + 0x10)) - 8;
	return BaseAddr;
}

BOOLEAN UpdateMmPfnDataBaseItem(ULONG64 PteAddress, PFN_NUMBER pfnNumber)
{

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	if (version.dwMajorVersion == 10)
	{
		ULONG64 mmdatabase = GetMmPfnDataBase();
		PULONG64 mmpfn = mmdatabase + (pfnNumber & 0xFFFFFFFFF) * 0x30;
		if (mmpfn && MmIsAddressValid(mmpfn))
		{
			mmpfn[0] = 1;
			mmpfn[1] = PteAddress;
			return TRUE;
		}
	}

	
	return FALSE;
}

ULONG64 GetPTE10(ULONG64 addr,ULONG BuildNumber)
{
	ULONG64 BaseAddr = 0;
	if (BuildNumber == 10586 || BuildNumber == 10240)
	{
		BaseAddr = PTE_BASE;
	}
	else 
	{ 
		BaseAddr = GetPteBase();
	}
	
	ULONG64 offset = (addr >> 9) & 0x7FFFFFFFF8L;
	return offset + BaseAddr;
}

ULONG64 GetPDE10(ULONG64 addr, ULONG BuildNumber)
{
	ULONG64 BaseAddr = 0;
	if (BuildNumber == 10586 || BuildNumber == 10240)
	{
		BaseAddr = PTE_BASE;
	}
	else
	{
		BaseAddr = GetPteBase();
	}
	ULONG64 PTE = GetPTE10(addr, BuildNumber);
	return ((PTE >> 9) & 0x7FFFFFFFF8L) + BaseAddr;
}

ULONG64 GetPPE10(ULONG64 addr, ULONG BuildNumber)
{
	ULONG64 BaseAddr = 0;
	if (BuildNumber == 10586 || BuildNumber == 10240)
	{
		BaseAddr = PTE_BASE;
	}
	else
	{
		BaseAddr = GetPteBase();
	}
	ULONG64 PDE = GetPDE10(addr, BuildNumber);
	return ((PDE >> 9) & 0x7FFFFFFFF8L) + BaseAddr;
}

ULONG64 GetPML410(ULONG64 addr, ULONG BuildNumber)
{
	ULONG64 BaseAddr = 0;
	if (BuildNumber == 10586 || BuildNumber == 10240)
	{
		BaseAddr = PTE_BASE;
	}
	else
	{
		BaseAddr = GetPteBase();
	}
	ULONG64 PPE = GetPPE10(addr, BuildNumber);
	return ((PPE >> 9) & 0x7FFFFFFFF8L) + BaseAddr;
}

ULONG64 GetPTE7(ULONG64 addr)
{
	return ((addr >> 9) & 0x7FFFFFFFF8L) + PTE_BASE;
}

ULONG64 GetPDE7(ULONG64 addr)
{
	return ((addr >> 18) & 0x3FFFFFF8L) + PDE_BASE;
}

ULONG64 GetPPE7(ULONG64 addr)
{
	return ((addr >> 27) & 0x1FFFF8) + PXE_BASE;
}

ULONG64 GetPML47(ULONG64 addr)
{
	return (((addr >> 39) & 0x1FFFF8) *8) + PML_BASE;
}

ULONG64 GetPTE(ULONG64 addr)
{
	RTL_OSVERSIONINFOW version = {0};
	RtlGetVersion(&version);
	if (version.dwMajorVersion == 10)
	{
		return GetPTE10(addr, version.dwBuildNumber);
	}

	return GetPTE7(addr);
}

ULONG64 GetPDE(ULONG64 addr)
{
	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	if (version.dwMajorVersion == 10)
	{
		return GetPDE10(addr, version.dwBuildNumber);
	}

	return GetPDE7(addr);
}

ULONG64 GetPPE(ULONG64 addr)
{
	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	if (version.dwMajorVersion == 10)
	{
		return GetPPE10(addr, version.dwBuildNumber);
	}
	
	return GetPPE7(addr);
}

ULONG64 GetPML4(ULONG64 addr)
{
	
	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	if (version.dwMajorVersion == 10)
	{
		return GetPML410(addr, version.dwBuildNumber);
	}

	return GetPML47(addr);
}

BOOLEAN SetExecutePage(ULONG64 baseAddr, SIZE_T size)
{
	int pageCount = ((size + 0xFFF) & ~0xFFF) >> 12;
	ULONG64 tempAddr = baseAddr;
	for (int i = 0; i< pageCount; i++)
	{
		HardwarePte * p = (HardwarePte *)GetPDE(tempAddr);
		if (MmIsAddressValid(p) && p->valid)
		{
			p->no_execute = 0;
			p->write = 1;
		}

		p = (HardwarePte *)GetPTE(tempAddr);
		if (MmIsAddressValid(p) && p->valid)
		{
			p->no_execute = 0;
			p->write = 1;

		}

		p = (HardwarePte *)GetPPE(tempAddr);
		if (MmIsAddressValid(p) && p->valid)
		{
			p->no_execute = 0;
			p->write = 1;

		}

		tempAddr += PAGE_SIZE;
	}
	return TRUE;
}

BOOLEAN SetPhyPage(ULONG64 VirtualAddress, ULONG64 size,ULONG_PTR * pageArr, ULONG pageNumber)
{
	ULONG64 tempAddr = VirtualAddress;
	ULONG64 pageCount = size >> 12;
	ULONG64 count = 0;
	for (int i = 0; i< pageCount && count < pageNumber; i++,count++)
	{
		HardwarePte * p = (HardwarePte *)GetPPE(tempAddr);
		if (MmIsAddressValid(p) && !p->valid)
		{
			ULONG64 initPte = (pageArr[count] << 12) | 0x867;
			memcpy(p, &initPte, sizeof(ULONG64));
			UpdateMmPfnDataBaseItem(p, pageArr[count]);
			count++;
		}

		p = (HardwarePte *)GetPDE(tempAddr);
		if (MmIsAddressValid(p) && !p->valid)
		{
			ULONG64 initPte = (pageArr[count] << 12) | 0x867;
			memcpy(p, &initPte, sizeof(ULONG64));
			UpdateMmPfnDataBaseItem(p, pageArr[count]);

			count++;
		}

		p = (HardwarePte *)GetPTE(tempAddr);
		if (MmIsAddressValid(p) && !p->valid)
		{
			ULONG64 initPte = (pageArr[count] << 12) | 0x867;
			UpdateMmPfnDataBaseItem(p, pageArr[count]);
			memcpy(p, &initPte, sizeof(ULONG64));
		}

		tempAddr += PAGE_SIZE;

	}
	return TRUE;
}

PVOID AllocateMemory(HANDLE pid, ULONG size)
{

	PEPROCESS Process = NULL;
	KAPC_STATE apcState = {0};
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	PVOID base = NULL;
	PVOID resultBase = NULL;
	SIZE_T usize = size;
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	KeStackAttachProcess(Process, &apcState);
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &usize, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
	if (NT_SUCCESS(status))
	{
		memset(base, 0, usize);
		
		SetExecutePage(base, usize);
		resultBase = base;
	}
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(Process);
	return resultBase;
}


BOOLEAN AttachPhyMemory(HANDLE pid,ULONG64 VirtualAddress,ULONG64 size,ULONG_PTR * pageArr, ULONG pageNumber)
{

	PEPROCESS Process = NULL;
	KAPC_STATE apcState = { 0 };
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
	BOOLEAN isAttachSuccess = FALSE;
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	KeStackAttachProcess(Process, &apcState);
	isAttachSuccess = SetPhyPage(VirtualAddress, size, pageArr, pageNumber);
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(Process);
	return isAttachSuccess;
}
