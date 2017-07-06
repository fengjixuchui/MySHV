/*++
Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:
    shvos.c

Abstract:
    This module implements the OS-facing Windows stubs for SimpleVisor.

Author:
    Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:
    Kernel mode only.
--*/

#include <ntifs.h>
#include <stdarg.h>
#include "shv_x.h"
#pragma warning(disable:4221)
#pragma warning(disable:4204)

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID KeGenericCallDpc (_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID KeSignalCallDpcDone (_In_ PVOID SystemArgument1);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL KeSignalCallDpcSynchronize (_In_ PVOID SystemArgument2);

DECLSPEC_NORETURN
VOID __cdecl ShvOsRestoreContext2 (_In_ PCONTEXT ContextRecord, _In_opt_ struct _EXCEPTION_RECORD * ExceptionRecord);

VOID ShvVmxCleanup (_In_ UINT16 Data, _In_ UINT16 Teb);

typedef struct _SHV_DPC_CONTEXT
{
    PSHV_CPU_CALLBACK Routine;
    struct _SHV_CALLBACK_CONTEXT* Context;
} SHV_DPC_CONTEXT, *PSHV_DPC_CONTEXT;

#define KGDT64_R3_DATA      0x28
#define KGDT64_R3_CMTEB     0x50

PVOID g_PowerCallbackRegistration;


NTSTATUS FORCEINLINE ShvOsErrorToError (INT32 Error)
{
    // Convert the possible SimpleVisor errors into NT Hyper-V Errors
    if (Error == SHV_STATUS_NOT_AVAILABLE)
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    if (Error == SHV_STATUS_NO_RESOURCES)
    {
        return STATUS_HV_NO_RESOURCES;
    }
    if (Error == SHV_STATUS_NOT_PRESENT)
    {
        return STATUS_HV_NOT_PRESENT;
    }
    if (Error == SHV_STATUS_SUCCESS)
    {
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;// Unknown/unexpected error
}


VOID ShvOsDpcRoutine (_In_ struct _KDPC *Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
    PSHV_DPC_CONTEXT dpcContext = DeferredContext;
    UNREFERENCED_PARAMETER(Dpc);

    dpcContext->Routine(dpcContext->Context);// Execute the internal callback function

    // During unload SimpleVisor uses the RtlRestoreContext function which will unfortunately use the "iretq" opcode in order to restore execution back.
    // This causes the processor to remove the RPL bits off the segments.
    // As the x64 kernel does not expect kernel-mode code to change the value of any segments, this results in the DS and ES segments being stuck 0x20,
    // and the FS segment being stuck at 0x50, until the next context switch.
    //
    // If the DPC happened to have interrupted either the idle thread or system thread, that's perfectly fine (albeit unusual).
    // If the DPC interrupted a 64-bit long-mode thread, that's also fine. However if the DPC interrupts
    // a thread in compatibility-mode, running as part of WoW64, it will hit a GPF instantenously and crash.
    //
    // Thus, set the segments to their correct value, one more time, as a fix.
    ShvVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);

    KeSignalCallDpcSynchronize(SystemArgument2);// Wait for all DPCs to synchronize at this point
    KeSignalCallDpcDone(SystemArgument1);// Mark the DPC as being complete
}


VOID ShvOsUnprepareProcessor (_In_ PSHV_VP_DATA VpData)
{
    // When running in VMX root mode, the processor will set limits of the GDT and IDT to 0xFFFF (notice that there are no Host VMCS fields to set these values).
    // This causes problems with PatchGuard, which will believe that the GDTR and IDTR have been modified by malware, and eventually crash the system.
    // Since we know what the original state of the GDTR and IDTR was, simply restore it now.
    __lgdt(&VpData->SpecialRegisters.Gdtr.Limit);
    __lidt(&VpData->SpecialRegisters.Idtr.Limit);
}


VOID PowerCallback (_In_opt_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    
    if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK)// Ignore non-Sx changes
    {
        return;
    }
    
    if (ARGUMENT_PRESENT(Argument2))// Check if this is S0->Sx, or Sx->S0
    {
        ShvLoad();// Reload the hypervisor
    }
    else
    {
        ShvUnload();// Unload the hypervisor
    }
}


VOID ShvOsFreeContiguousAlignedMemory (_In_ PVOID BaseAddress)
{
    MmFreeContiguousMemory(BaseAddress);// Free the memory
}


PVOID ShvOsAllocateContigousAlignedMemory (_In_ SIZE_T Size)
{
    PHYSICAL_ADDRESS lowest, highest;

    // The entire address range is OK for this allocation
    lowest.QuadPart = 0;
    highest.QuadPart = lowest.QuadPart - 1;

    // Allocate a contiguous chunk of RAM to back this allocation and make sure that it is RW only, instead of RWX, by using the new Windows 8 API.
    return MmAllocateContiguousNodeMemory(Size, lowest, highest, lowest, PAGE_READWRITE, KeGetCurrentNodeNumber());
}


ULONGLONG ShvOsGetPhysicalAddress (_In_ PVOID BaseAddress)
{
    return MmGetPhysicalAddress(BaseAddress).QuadPart;// Let the memory manager convert it
}


VOID RunCallbackOnProcessors(_In_ PSHV_CPU_CALLBACK Routine, _In_opt_ PVOID Context)
{
    SHV_DPC_CONTEXT dpcContext;

    // Wrap the internal routine and context under a Windows DPC
    dpcContext.Routine = Routine;
    dpcContext.Context = Context;
    KeGenericCallDpc(ShvOsDpcRoutine, &dpcContext);
}


VOID ShvOsRestoreContext(_In_ PCONTEXT ContextRecord)
{
    ShvOsRestoreContext2(ContextRecord, NULL);
}


VOID ShvOsCaptureContext (_In_ PCONTEXT ContextRecord)
{
    RtlCaptureContext(ContextRecord);// Windows provides a nice OS function to do this
}


INT32 ShvOsGetCurrentProcessorNumber (VOID)
{
    return (INT32)KeGetCurrentProcessorNumberEx(NULL);// Get the group-wide CPU index
}


INT32 ShvOsGetActiveProcessorCount (VOID)
{
    return (INT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);// Get the group-wide CPU count
}


VOID ShvOsDebugPrint (_In_ PCCH Format, ...)
{
    va_list arglist;
    
    va_start(arglist, Format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, arglist);// Call the debugger API
    va_end(arglist);
}


VOID DriverUnload (_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    ExUnregisterCallback(g_PowerCallbackRegistration);// Unregister the power callback. We would not have loaded without it
    ShvUnload();// Unload the hypervisor
}


NTSTATUS DriverEntry (_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PCALLBACK_OBJECT callbackObject;
    UNICODE_STRING callbackName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&callbackName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

    UNREFERENCED_PARAMETER(RegistryPath);

    __debugbreak();

    DriverObject->DriverUnload = DriverUnload;// Make the driver (and SHV itself) unloadable

    status = ExCreateCallback(&callbackObject, &objectAttributes, FALSE, TRUE);// Create the power state callback
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_PowerCallbackRegistration = ExRegisterCallback(callbackObject, PowerCallback, NULL);// Now register our routine with this callback
    // Dereference it in both cases -- either it's registered, so that is now taking a reference,
    // and we'll unregister later, or it failed to register so we failing now, and it's gone.
    ObDereferenceObject(callbackObject);    
    if (g_PowerCallbackRegistration == NULL)// Fail if we couldn't register the power callback
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return ShvOsErrorToError(ShvLoad());// Load the hypervisor
}
