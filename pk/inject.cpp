// FileName : KernelFuncInject.cpp
// Creator : PeterZheng
// Date : 2019/01/10 21:32
// Comment : Use Kernel Function To Inject
//
////////////////////////////////

#pragma once
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <strsafe.h>
#include <Windows.h>
#include <TlHelp32.h>

#ifdef _WIN64
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown);
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown);
#endif

using namespace std;

// 提权函数
BOOL EnableDebugPriv(LPCSTR name)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	// 打开进程令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("[!]Get Process Token Error!\n");
		return false;
	}
	// 获取权限Luid
	if (!LookupPrivilegeValue(NULL, name, &luid))
	{
		printf("[!]Get Privilege Error!\n");
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 修改进程权限
	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("[!]Adjust Privilege Error!\n");
		return false;
	}
	return true;
}

// 根据进程名字获取进程Id
BOOL GetProcessIdByName(CHAR* szProcessName, DWORD& dwPid)
{
	HANDLE hSnapProcess = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapProcess == NULL)
	{
		printf("[*] Create Process Snap Error!\n");
		return FALSE;
	}
	PROCESSENTRY32 pe32 = { 0 };
	::RtlZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	BOOL bRet = ::Process32First(hSnapProcess, &pe32);
	while (bRet)
	{
		if (_stricmp(pe32.szExeFile, szProcessName) == 0)
		{
			dwPid = pe32.th32ProcessID;
			return TRUE;
		}
		bRet = ::Process32Next(hSnapProcess, &pe32);
	}
	return FALSE;
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("[*] Format Error!  \nYou Should FOLLOW THIS FORMAT: <APCInject EXENAME DLLNAME> \n");
		return 0;
	}
	LPSTR szExeName = (LPSTR)::VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	LPSTR szDllPath = (LPSTR)::VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	::RtlZeroMemory(szExeName, 100);
	::RtlZeroMemory(szDllPath, 100);
	::StringCchCopy(szExeName, 100, argv[1]);
	::StringCchCopy(szDllPath, 100, argv[2]);
	DWORD dwPid = 0;
	// 系统进程必须先提权才能打开，否则在OpenProcess步骤会失败
	EnableDebugPriv(SE_DEBUG_NAME);
	BOOL bRet = GetProcessIdByName(szExeName, dwPid);
	if (!bRet)
	{
		printf("[*] Get Process Id Error!\n");
		return 0;
	}
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		printf("[*] Open Process Error!\n");
		return 0;
	}
	DWORD dwDllPathLen = strlen(szDllPath) + 1;
	LPVOID lpBaseAddress = ::VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		printf("[*] VirtualAllocEx Error!\n");
		return 0;
	}
	SIZE_T dwWriten = 0;
	// 把DLL路径字符串写入目标进程
	::WriteProcessMemory(hProcess, lpBaseAddress, szDllPath, dwDllPathLen, &dwWriten);
	if (dwWriten != dwDllPathLen)
	{
		printf("[*] Write Process Memory Error!\n");
		return 0;
	}
	// 获取LoadLibrary函数地址
	LPVOID pLoadLibraryFunc = ::GetProcAddress(::GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pLoadLibraryFunc == NULL)
	{
		printf("[*] Get Func Address Error!\n");
		return 0;
	}
	HMODULE hNtdll = ::LoadLibrary("ntdll.dll");
	if (hNtdll == NULL)
	{
		printf("[*] Load NtDLL Error!\n");
		return 0;
	}
	typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)::GetProcAddress(hNtdll, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		printf("[*] Get NTDLL Func Address Error!\n");
		return 0;
	}
	DWORD dwStatus = 0;
	HANDLE hRemoteThread = NULL;
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryFunc, lpBaseAddress, 0, 0, 0, 0, NULL);
	if (hRemoteThread == NULL)
	{
		printf("[*] Create Remote Thread Error!\n");
		return 0;
	}

	// DLL路径分割，方便输出
	LPCSTR szPathSign = "\\";
	LPSTR p = NULL;
	LPSTR next_token = NULL;
	p = strtok_s(szDllPath, szPathSign, &next_token);
	while (p)
	{
		StringCchCopy(szDllPath, 100, p);
		p = strtok_s(NULL, szPathSign, &next_token);
	}
	printf("[*] High Privilege Inject Info [%s ==> %s] Success\n", szDllPath, szExeName);

	::CloseHandle(hProcess);
	::FreeLibrary(hNtdll);
	::VirtualFree(szExeName, 0, MEM_RELEASE);
	::VirtualFree(szDllPath, 0, MEM_RELEASE);
	::ExitProcess(0);
	return 0;

}