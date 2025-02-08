#pragma once

#include "macros.h"
#include "FindProcesses.h"
#include "driver_defs.h"

#include <ntifs.h>
#include <wdm.h>
#include <sal.h>


/**
	Function: GetProcessImageInfo - this gets the base image of the address for the given process id
	Args:
		irp - I/O request packet for given function to communicate at kernel-level
		ProcessId - the process id to get base image of
		ImageInfo - struct to store the name and base address of the process id
	Return:
		status of operations required to perform actions

*/
NTSTATUS GetProcessImageInfo(_Inout_ PIRP irp, _In_ HANDLE ProcessId, _Inout_ PProcessImageInfo ImageInfo) {

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process;

	// Lookup the process by ID
	status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status)) {
		irp->IoStatus.Status = status;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	//get the base address for the given process
	PVOID addr = PsGetProcessSectionBaseAddress(process);

	// check to see if the address is null
	if (addr == NULL) {
		// addr not available
		ObDereferenceObject(process);
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	// get the name of the process if applicable
	PUCHAR name = PsGetProcessImageFileName(process);

	ImageInfo->ImageBase = addr;
	RtlCopyMemory(ImageInfo->ImageName, name, strlen(name) + sizeof(UCHAR));
	DbgPrint("[csdrv] Process address is the following: %p for pid %d name %s\n", addr, ProcessId, name);
	
	// Dereference the process object
	ObDereferenceObject(process);


	// return status success
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(ProcessImageInfo);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	status = STATUS_SUCCESS;
	return status;
}

/**
	Function: GetProcessList - this gets ALL process ids that are running on the system - more powerful than doing in user-mode
	Args:
		irp - I/O request packet for given function to communicate at kernel-level
		io - I/O tracking purposes for kernel to keep track of operation
	Return:
		status of operations required to perform actions

*/
NTSTATUS GetProcessList(_Inout_ PIRP irp, _Inout_ PIO_STACK_LOCATION io)
{
	ULONG count = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	_ZwQuerySystemInformation ZwQuerySystemInformation = NULL;
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = NULL;
	ULONG size = MAXULONG;

	// Get kernel function ZwQuerySystemInformation to get the SYSTEM_PROCESS_INFORMATION struct
	UNICODE_STRING uZwQuerySystemInformation = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&uZwQuerySystemInformation);
	PLIST* given_memory = NULL;


	if (!ZwQuerySystemInformation) {
		DbgPrint("[csdrv] Failed to get address of ZwQuerySystemInformation\n");
		return STATUS_UNSUCCESSFUL;
	}

	pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'tag');
	if (!pSysProcInfo) {
		DbgPrint("[csdrv] Failed to allocate memory for SYSTEM_PROCESS_INFORMATION\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}

	// Get the struct stored in pSysProcInfo and get the size associated with this process struct
	status = ZwQuerySystemInformation(SystemProcessInformation, pSysProcInfo, size, &size);

	// if the size that was passed was too small, reallocate and try again
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePoolWithTag(pSysProcInfo, 'tag');
		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'tag');

		// only come to here if the allocation failed
		if (!pSysProcInfo) {
			DbgPrint("[csdrv] Failed to allocate memory for SYSTEM_PROCESS_INFORMATION\n");
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			status = STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pSysProcInfo, size, &size);
	}


	// if thiis system operation was successful, we can determine whether to only return the size or also get all processes
	if (NT_SUCCESS(status)) {

		// the user-level passed buffer will determine whether this was just to return the count, or the processes
		if (!MmIsAddressValid(irp->AssociatedIrp.SystemBuffer)) {
			PSYSTEM_PROCESS_INFORMATION pInfo = pSysProcInfo;

			while (pInfo) {
				if (pInfo->NextEntryOffset == 0) {
					break;
				}

				count += 1;
				pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
			}

			// this only gets called if the operation itself for getting the size is done
			ExFreePoolWithTag(pSysProcInfo, 'tag');
			DbgPrint("[csdrv] input buffer is null - we just wanted the count\n");
			irp->IoStatus.Information = count;
			irp->IoStatus.Status = STATUS_SUCCESS;
			status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}
		
		// convert the user-level buffer into the associated PLIST struct that is needed to get the process ids
		PSYSTEM_PROCESS_INFORMATION pInfo = pSysProcInfo;
		given_memory = (PLIST*)(irp->AssociatedIrp.SystemBuffer);
		IO_STACK_LOCATION* CurrentStackLocation = irp->Tail.Overlay.CurrentStackLocation;
		ULONG output_size = CurrentStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG limit_size = output_size / sizeof(HANDLE);

		
		DbgPrint("[csdrv] The buffer size for this is: %d\n", size);
		
		// traverse and get the process ids to get stored into the struct list
		while (pInfo) {
			if (pInfo->NextEntryOffset == 0 || count >= limit_size) {
				break;
			}
			RtlCopyMemory(&(given_memory[count].ProcessID), &((pInfo->UniqueProcessId)), sizeof(HANDLE));
			DbgPrint("[csdrv] [%d] [%d]\n", pInfo->UniqueProcessId, given_memory[count]);
			count += 1;
			pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
		}
	}
	else {
		DbgPrint("[csdrv] Failed to retrieve process information\n");
	}

	// deallocate and return
	ExFreePoolWithTag(pSysProcInfo, 'tag');
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = count * sizeof(given_memory);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	status = STATUS_SUCCESS;
	return status;
}


/**
	Function: KillProcess - this GUARANTEES the process to be killed - dangerous to be called carelessly but effective if malicious programs cannot be easily killed
	Args:
		irp - I/O request packet for given function to communicate at kernel-level
		ProcessId - process to kill
	Return:
		status of operations required to perform actions

*/
NTSTATUS KillProcess(_Inout_ PIRP irp, _In_ HANDLE ProcessId) {
	PEPROCESS Process;
	NTSTATUS status = STATUS_SUCCESS;

	// get the process id from kernel level
	if (!NT_SUCCESS(status = PsLookupProcessByProcessId(ProcessId, &Process))) {
		return status;
	}
	
	// this unmaps the memory of the process id within the system - gets the base address of process's executable image and unmap it
	status = MmUnmapViewOfSection(Process, PsGetProcessSectionBaseAddress(Process));

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	// Dereference the target process
	ObDereferenceObject(Process); 

	return status;

}


/**
	Function: Operation - this is what directs the DeviceIoControl function at the user-level for direction of what function to call
	Args:
		DeviceObject - un-used parameter
		irp - I/O request packet for given function to communicate at kernel-level
	Return:
		status of operations required to perform actions

*/
NTSTATUS Operations(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP irp)
{
	ULONG count = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNREFERENCED_PARAMETER(DeviceObject);

	PLIST* given_memory = NULL;
	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);

	// get the IO control node to see what operation to run
	switch (io->Parameters.DeviceIoControl.IoControlCode)
	{
		// get processes
		case IOCTL_GET_PROCESSES: {
			status = GetProcessList(irp, io);

			break;
		}
		// get image info of process
		case IOCTL_GET_IMAGE_INFO: {
			HANDLE processID = -1;
			RtlCopyMemory(&processID, irp->AssociatedIrp.SystemBuffer, sizeof(ULONGLONG));

			status = GetProcessImageInfo(irp, processID, irp->AssociatedIrp.SystemBuffer);
			break;
		}

		// kill given process
		case IOCTL_KILL_PROCESS: {
			HANDLE processID = -1;
			RtlCopyMemory(&processID, irp->AssociatedIrp.SystemBuffer, sizeof(ULONGLONG));

			status = KillProcess(irp, processID);
			break;
		}

		// default case
		default: {
			DbgPrint("[csdrv] Unknown IOCTL code: %#x\n", io->Parameters.DeviceIoControl.IoControlCode);
			DbgPrint("[csdrv] In DEFAULT case.\n");

			irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = count;

			IoCompleteRequest(irp, IO_NO_INCREMENT);
			status = STATUS_INVALID_DEVICE_REQUEST;
		}
	}

	return status;
}

/**
	Function: DriverUnload - needed for unloading the driver off of the system
	Args:
		dob - driver object too be unloading
	Return:
		NONE
*/
VOID DriverUnload(_Inout_ PDRIVER_OBJECT dob) {
	UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(DEVICE_LINK_MACRO);
	DbgPrint("[csdrv] Driver unloaded, deleting symbolic links and devices");
	IoDeleteDevice(dob->DeviceObject);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
}

/**
	Function: Write - needed for IRP I/O write requests
	Args:
		irp and device objects are not needed for this function, but are passed anyways
	Return:
		status_success by default
*/
NTSTATUS Write(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return status;
}

/**
	Function: Close - needed for IRP I/O close requests
	Args:
		irp and device objects are not needed for this function, but are passed anyways
	Return:
		status_success by default
*/
NTSTATUS Close(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return status;
}

/**
	Function: Create - needed for IRP I/O create requests
	Args:
		irp and device objects are not needed for this function, but are passed anyways
	Return:
		status_success by default
*/
NTSTATUS Create(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return status;
}


/**
* 
	Function: DriverEntry - entry point to call driver for operation
	Args:
		DriverObject - information to be used for setting up driver's operations and controls
		RegistryPath - unreferenced but required as a parameter
	Return:
		status of operations required to perform actions
		
*/
NTSTATUS DriverEntry(_Inout_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	// Strings associated with driver name for unlinking and linking purposes
	UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(DEVICE_NAME_MACRO);
	UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(DEVICE_LINK_MACRO);
	PDEVICE_OBJECT DeviceObject;

	/* Create the Io Device */
	NTSTATUS status = IoCreateDevice(
		DriverObject, // our driver object
		0, // no need for extra bytes
		&DEVICE_NAME, // the device name
		FILE_DEVICE_SECURE_OPEN, // device type
		0, // characteristics flags
		FALSE, // not exclusive
		&DeviceObject); // the resulting pointer

	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	};
	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;

	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = Write;

	// Operations being setup for driver purposes
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Operations;
	DbgPrint("[csdrv] Driver loading attempt\n");

	if (!NT_SUCCESS(status)) {
		DbgPrint("[csdrv] Could not create device %wZ\n", DEVICE_NAME);
		IoDeleteDevice(DeviceObject); // important!
		return status;
	}
	else {
		DbgPrint("[csdrv] Device %wZ created\n", DEVICE_NAME);
	}

	// linking needed for system references - to be called that is
	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[csdrv] Error creating symbolic link %wZ\n", DEVICE_SYMBOLIC_NAME);
		IoDeleteDevice(DeviceObject); // important!
		return status;
	}
	else {
		DbgPrint("[csdrv] Symbolic link %wZ created\n", DEVICE_SYMBOLIC_NAME);
	}

	return STATUS_SUCCESS;
}