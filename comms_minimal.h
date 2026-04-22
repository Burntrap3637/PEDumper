#pragma once
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>

#define code_read       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_write      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_cr3    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_process_base CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_peb    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Structure definitions
typedef struct _ReadInvoke {
	uint32_t Pid;
	uint32_t Padding;
	uint64_t Address;
	void* Buffer;
	size_t Size;
	uint64_t Cr3;
} ReadInvoke, *PReadInvoke;

typedef struct _WriteInvoke {
	uint32_t Pid;
	uint32_t Padding;
	uint64_t Address;
	void* Buffer;
	size_t Size;
	uint64_t Cr3;
} WriteInvoke, *PWriteInvoke;

typedef struct _GetCr3Invoke {
	uint32_t Pid;
	uint64_t Cr3Attach;
	uint64_t Cr3Brute;
} GetCr3Invoke, *PGetCr3Invoke;

typedef struct _GetProcessBaseInvoke {
	uint32_t Pid;
	uint32_t Padding;
	uint64_t OutputAddress;
} GetProcessBaseInvoke, *PGetProcessBaseInvoke;

typedef struct _GetPebInvoke {
	uint32_t Pid;
	uint32_t Padding;
	uint64_t Peb;
} GetPebInvoke, *PGetPebInvoke;

class Driver
{
private:
	uint64_t CurrentCr3;
	HANDLE DriverHandle;

public:
	uint32_t ProcessId;

	Driver()
	{
		ProcessId = 0;
		DriverHandle = INVALID_HANDLE_VALUE;
		CurrentCr3 = 0;
	}

	~Driver()
	{
		if (DriverHandle != INVALID_HANDLE_VALUE)
			CloseHandle(DriverHandle);
	}

	__forceinline void Setup(HANDLE Handle)
	{
		DriverHandle = Handle;
		CurrentCr3 = 0;
	}

	__forceinline uint32_t Target(const wchar_t* ProcessName)
	{
		PROCESSENTRY32 Entry;
		Entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Snapshot == INVALID_HANDLE_VALUE)
			return 0;

		if (Process32First(Snapshot, &Entry))
		{
			do
			{
				if (wcscmp(Entry.szExeFile, ProcessName) == 0)
				{
					ProcessId = Entry.th32ProcessID;
					CloseHandle(Snapshot);
					return ProcessId;
				}
			} while (Process32Next(Snapshot, &Entry));
		}

		CloseHandle(Snapshot);
		return 0;
	}

	__forceinline uint32_t GetProcessId()
	{
		return ProcessId;
	}

	__forceinline void UpdateCr3()
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return;

		GetCr3Invoke Request = { 0 };
		Request.Pid = ProcessId;
		Request.Cr3Attach = 0;
		Request.Cr3Brute = 0;

		DWORD BytesReturned = 0;
		if (DeviceIoControl(DriverHandle, code_get_cr3, &Request, sizeof(Request), &Request, sizeof(Request), &BytesReturned, 0))
		{
			if (Request.Cr3Brute != 0)
				CurrentCr3 = Request.Cr3Brute;
			else if (Request.Cr3Attach != 0)
				CurrentCr3 = Request.Cr3Attach;
		}
	}

	__forceinline uint64_t GetCr3()
	{
		return CurrentCr3;
	}

	__forceinline uint64_t GetProcessBase()
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return 0;

		GetProcessBaseInvoke Request = { 0 };
		Request.Pid = ProcessId;
		Request.OutputAddress = 0;

		DWORD BytesReturned = 0;
		if (DeviceIoControl(DriverHandle, code_get_process_base, &Request, sizeof(Request), &Request, sizeof(Request), &BytesReturned, 0))
			return Request.OutputAddress;

		return 0;
	}

	__forceinline uint64_t GetPeb()
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return 0;

		GetPebInvoke Request = { 0 };
		Request.Pid = ProcessId;
		Request.Peb = 0;

		DWORD BytesReturned = 0;
		if (DeviceIoControl(DriverHandle, code_get_peb, &Request, sizeof(Request), &Request, sizeof(Request), &BytesReturned, 0))
			return Request.Peb;

		return 0;
	}

	__forceinline bool Read(uint64_t Address, void* Buffer, size_t Size)
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return false;

		ReadInvoke Request;
		Request.Pid = ProcessId;
		Request.Address = Address;
		Request.Buffer = Buffer;
		Request.Size = Size;
		Request.Cr3 = CurrentCr3;

		DWORD BytesReturned = 0;
		return DeviceIoControl(DriverHandle, code_read, &Request, sizeof(Request), &Request, sizeof(Request), &BytesReturned, 0);
	}

	__forceinline bool Write(uint64_t Address, void* Buffer, size_t Size)
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return false;

		WriteInvoke Request;
		Request.Pid = ProcessId;
		Request.Address = Address;
		Request.Buffer = Buffer;
		Request.Size = Size;
		Request.Cr3 = CurrentCr3;

		DWORD BytesReturned = 0;
		return DeviceIoControl(DriverHandle, code_write, &Request, sizeof(Request), &Request, sizeof(Request), &BytesReturned, 0);
	}

	template<typename T>
	__forceinline T Read(uint64_t Address)
	{
		T Value = { 0 };
		Read(Address, &Value, sizeof(T));
		return Value;
	}

	template<typename T>
	__forceinline bool Write(uint64_t Address, T Value)
	{
		return Write(Address, &Value, sizeof(T));
	}
};
