#include <windows.h>
#include <stdio.h>

#define IOCTL_MONITOR_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MONITOR_PROCESS_REQUEST {
    ULONG Pid;
} MONITOR_PROCESS_REQUEST, *PMONITOR_PROCESS_REQUEST;

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    HANDLE hDevice = CreateFile(L"\\\\.\\ProcMonitor", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open device (error code %lu)\n", GetLastError());
        return 1;
    }

    ULONG Pid = (ULONG)atoi(argv[1]);
    MONITOR_PROCESS_REQUEST Request;
    Request.Pid = Pid;

    DWORD BytesReturned;
    BOOL Result = DeviceIoControl(hDevice, IOCTL_MONITOR_PROCESS, &Request, sizeof(Request), NULL, 0, &BytesReturned, NULL);
    if (!Result) {
        printf("Error: DeviceIoControl failed (error code %lu)\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("Successfully sent request to monitor PID %lu\n", Pid);
    CloseHandle(hDevice);

    return 0;
}
