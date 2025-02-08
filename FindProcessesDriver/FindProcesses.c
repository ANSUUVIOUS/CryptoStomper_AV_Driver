#pragma once

#include "macros.h"
#include "FindProcesses.h"
#include "driver_defs.h"

#include <ntifs.h>
#include <wdm.h>


NTSTATUS GetProcessImageInfo(PIRP irp, HANDLE ProcessId, PProcessImageInfo ImageInfo) {

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process;

	//// Lookup the process by ID
	status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status)) {
		irp->IoStatus.Status = status;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	PVOID addr = PsGetProcessSectionBaseAddress(process);

	if (addr == NULL) {
		// addr not available
		ObDereferenceObject(process);
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	PUCHAR name = PsGetProcessImageFileName(process);

	ImageInfo->ImageBase = addr;
	RtlCopyMemory(ImageInfo->ImageName, name, strlen(name) + sizeof(UCHAR));
	DbgPrint("Process address is the following: %p for pid %d name %s\n", addr, ProcessId, name);
	//// Dereference the process object
	ObDereferenceObject(process);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(ProcessImageInfo);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	status = STATUS_SUCCESS;
	return status;
}

NTSTATUS GetProcessList(PIRP irp, PIO_STACK_LOCATION io)
{
	ULONG count = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	_ZwQuerySystemInformation ZwQuerySystemInformation = NULL;
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = NULL;
	ULONG size = MAXULONG;

	UNICODE_STRING uZwQuerySystemInformation = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&uZwQuerySystemInformation);
	PLIST* given_memory = NULL;

	DbgPrint("PrintProcessList\n");

	if (!ZwQuerySystemInformation)
	{
		DbgPrint("[acdrv] Failed to get address of ZwQuerySystemInformation\n");
		return STATUS_UNSUCCESSFUL;
	}

	pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'tag');
	if (!pSysProcInfo)
	{
		DbgPrint("[acdrv] 1 Failed to allocate memory for SYSTEM_PROCESS_INFORMATION\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, pSysProcInfo, size, &size);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePoolWithTag(pSysProcInfo, 'tag');
		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'tag');
		if (!pSysProcInfo)
		{
			DbgPrint("[acdrv] 2 Failed to allocate memory for SYSTEM_PROCESS_INFORMATION\n");
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			status = STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pSysProcInfo, size, &size);
	}

	//PVOID addr = pSysProcInfo;
	if (NT_SUCCESS(status))
	{
		if (!MmIsAddressValid(irp->AssociatedIrp.SystemBuffer))
		{
			//going to count the amount of processes
			PSYSTEM_PROCESS_INFORMATION pInfo = pSysProcInfo;

			while (pInfo)
			{
				if (pInfo->NextEntryOffset == 0)
				{
					break;
				}

				count += 1;
				pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
			}

			ExFreePoolWithTag(pSysProcInfo, 'tag');
			DbgPrint("input buffer is null - we just wanted the count\n");
			irp->IoStatus.Information = count;
			irp->IoStatus.Status = STATUS_SUCCESS;
			status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		PSYSTEM_PROCESS_INFORMATION pInfo = pSysProcInfo;
		given_memory = (PLIST*)(irp->AssociatedIrp.SystemBuffer);
		IO_STACK_LOCATION* CurrentStackLocation = irp->Tail.Overlay.CurrentStackLocation;
		ULONG output_size = CurrentStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG limit_size = output_size / sizeof(HANDLE);

		DbgPrint("The buffer size for this is: %d\n");
		while (pInfo)
		{
			//DbgPrint("[acdrv] [%d] %wZ (threads: %d)\n", pInfo->UniqueProcessId, &pInfo->ImageName, pInfo->NumberOfThreads);
			if (pInfo->NextEntryOffset == 0 || count >= limit_size)
			{
				break;
			}
			RtlCopyMemory(&(given_memory[count].ProcessID), &((pInfo->UniqueProcessId)), sizeof(HANDLE));
			DbgPrint("[acdrv] [%d] [%d]\n", pInfo->UniqueProcessId, given_memory[count]);
			count += 1;
			pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
		}
	}
	else
	{
		DbgPrint("[acdrv] Failed to retrieve process information\n");
	}

	ExFreePoolWithTag(pSysProcInfo, 'tag');
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = count * sizeof(given_memory);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	status = STATUS_SUCCESS;
	return status;
}


NTSTATUS KillProcess(PIRP irp, HANDLE ProcessId) {
	PEPROCESS Process;
	NTSTATUS status = STATUS_SUCCESS;


	if (!NT_SUCCESS(status = PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		return status;
	}

	status = MmUnmapViewOfSection(Process, PsGetProcessSectionBaseAddress(Process)); // Get the base address of process's executable image and unmap it

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	ObDereferenceObject(Process); // Dereference the target process

	return status;

}

NTSTATUS Operations(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	ULONG count = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNREFERENCED_PARAMETER(DeviceObject);
	//UNREFERENCED_PARAMETER(irp);

	PLIST* given_memory = NULL;
	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);

	//DbgPrint("%ld vs. %ld", io->Parameters.DeviceIoControl.IoControlCode, IOCTL_GET_PROCESSES);
	switch (io->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_GET_PROCESSES: {
			status = GetProcessList(irp, io);

			break;
		}
		case IOCTL_GET_IMAGE_INFO: {
			HANDLE processID = -1;
			RtlCopyMemory(&processID, irp->AssociatedIrp.SystemBuffer, sizeof(ULONGLONG));

			status = GetProcessImageInfo(irp, processID, irp->AssociatedIrp.SystemBuffer);
			break;
		}
		case IOCTL_KILL_PROCESS: {
			HANDLE processID = -1;
			RtlCopyMemory(&processID, irp->AssociatedIrp.SystemBuffer, sizeof(ULONGLONG));

			status = KillProcess(irp, processID);
			break;
		}
		default: {
			DbgPrint("Unknown IOCTL code: %#x\n", io->Parameters.DeviceIoControl.IoControlCode);

			DbgPrint("In DEFAULT case.\n");

			irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = count;

			IoCompleteRequest(irp, IO_NO_INCREMENT);
			status = STATUS_INVALID_DEVICE_REQUEST;
		}
	}

	return status;
}



void DriverUnload(PDRIVER_OBJECT dob) {
	UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(DEVICE_LINK_MACRO);
	DbgPrint("Driver unloaded, deleting symbolic links and devices");
	IoDeleteDevice(dob->DeviceObject);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
}

NTSTATUS Write(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return status;
}

NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return status;
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

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

	//RtlCopyMemory(blockpid, L"notepad", sizeof(WCHAR) * wcslen(L"notepad"));
	//size = sizeof(WCHAR) * wcslen(L"notepad");

	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;

	// routine for handling IO requests from userland
	//DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleCustomIOCTL;

	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = Write;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Operations;
	DbgPrint("Driver loaded\n");

	//status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Could not create device %wZ\n", DEVICE_NAME);
		IoDeleteDevice(DeviceObject); // important!
		return status;
	}
	else {
		DbgPrint("Device %wZ created\n", DEVICE_NAME);
	}

	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error creating symbolic link %wZ\n", DEVICE_SYMBOLIC_NAME);
		IoDeleteDevice(DeviceObject); // important!
		return status;
	}
	else {
		DbgPrint("Symbolic link %wZ created\n", DEVICE_SYMBOLIC_NAME);
	}

	return STATUS_SUCCESS;
}