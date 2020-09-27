/************************************************************
*                     Author:Pluviophile                    *
*                    Date:2020/9/27-23:03                   *
*     E-Mail:1565203609@qq.com/pluviophile12138@outlook.com *
*         远线程注入，将DllPath指定的dll注入指定的进程      *
*************************************************************/

#pragma once
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

/*判断系统架构，并定义ZwCreateThreadEx函数指针*/
#ifdef _WIN64
typedef	DWORD(WINAPI* pZwCreateThreadEx)(
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
	LPVOID pUnkown
	);
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
	LPVOID pUnkown
	);
#endif

/*
设定本进程的程序调试权限
lPcstr:权限字符串
backCode:错误返回码
*/
BOOL GetDebugPrivilege(
_In_ LPCSTR lPcstr,
_Inout_ DWORD* backCode
)
{
	HANDLE Token = NULL;
	LUID luid = { 0 };
	TOKEN_PRIVILEGES Token_privileges = { 0 };
	//内存初始化为zero
	memset(&luid, 0x00, sizeof(luid));
	memset(&Token_privileges, 0x00, sizeof(Token_privileges));

	//打开进程令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token))
	{
		*backCode = 0x01;
		return FALSE;
	}

	//获取特权luid
	if (!LookupPrivilegeValue(NULL,lPcstr,&luid))
	{
		*backCode = 0x02;
		return FALSE;
	}

	//设定结构体luid与特权
	Token_privileges.PrivilegeCount = 1;
	Token_privileges.Privileges[0].Luid = luid;
	Token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//修改进程特权
	if (!AdjustTokenPrivileges(Token, FALSE, &Token_privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		*backCode = 0x03;
		return FALSE;
	}
	*backCode = 0x00;
	return TRUE;
}

/*
根据进程名获取进程pid，执行无误返回进程pid，出错返回-1
ProcessName:进程名
backCode:错误返回码
*/
int GetProcessPid(
	_In_ const char* ProcessName,
	_Inout_ DWORD* backCode
)
{
	PROCESSENTRY32 P32 = { 0 };
	HANDLE H32 = NULL;
	//内存初始化为zeor
	memset(&P32, 0X00, sizeof(P32));
	//创建快照
	H32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	P32.dwSize = sizeof(P32);
	if (H32 == NULL)
	{
		*backCode = 0x01;
		return -1;
	}
	//开始循环遍历进程
	BOOL ret = Process32First(H32, &P32);
	while (ret)
	{
		//发现指定进程存在
		if (!strcmp(P32.szExeFile, ProcessName))
		{
			*backCode = 0x00;
			return P32.th32ProcessID;
		}
		ret = Process32Next(H32, &P32);
	}
	*backCode = 0x01;
	return -1;
}

/*
主函数
*/
int main(int argv, char* argc[])
{
	//对必要的变量进行声明以及初始化
	DWORD backCode = 0;
	HANDLE hProcess = NULL;
	LPVOID Buff = NULL;
	LPVOID LoadLibraryBase = NULL;
	char DllPath[] = "D:\\cp\\pk\\x64\\Release\\pk.dll";
	DWORD DllPathLen = strlen(DllPath) + 1;
	HMODULE Ntdll = NULL;
	SIZE_T write_len = 0;
	DWORD dwStatus = 0;
	HANDLE hRemoteThread = NULL;

	//通过进程名获取pid
	int pid = GetProcessPid("notepad.exe", &backCode);
	if (pid == -1)
	{
		puts("pid get error");
		return 0;
	}

	//提升进程特权，获得调试权限
	if (!GetDebugPrivilege(SE_DEBUG_NAME, &backCode))
	{
		puts("DBG privilege error");
		printf(" %d", backCode);
		return 0;
	}

	//打开要被注入的进程
	if ((hProcess=OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid))== NULL)
	{
		puts("process open erro");
		return 0;
	}

	//在要被注入的进程中创建内存，用于存放注入dll的路径
	Buff = VirtualAllocEx(hProcess, NULL, DllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (Buff==NULL)
	{
		puts("Buff alloc error");
		return 0;
	}

	//将dll路径写入刚刚创建的内存中
	WriteProcessMemory(hProcess, Buff, DllPath, DllPathLen, &write_len);
	if(DllPathLen != write_len)
	{
		puts("write error");
		return 0;
	}

	//从kernel32.dll中获取LoadLibrary函数
	LoadLibraryBase = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (LoadLibraryBase == NULL)
	{
		puts("kernel32 get error");
		return 0;
	}

	//加载ntdll.dll并从中获取内核函数ZwCreateThread，并使用函数指针指向此函数
	Ntdll = LoadLibrary("ntdll.dll");
	pZwCreateThreadEx ZwCreateThreadEx = 
		(pZwCreateThreadEx)GetProcAddress(Ntdll, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		puts("func get error");
		return 0;
	}

	//执行ZwCreateThread函数，在指定进程中创建线程加载要被注入的dll
	dwStatus = ZwCreateThreadEx(
		&hRemoteThread,
		PROCESS_ALL_ACCESS,
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)LoadLibraryBase,
		Buff,
		0, 0, 0, 0,
		NULL
	);
	if (hRemoteThread == NULL)
	{
		puts("zwcreatethread fun error");
		return 0;
	}

	//释放不需要的变量以及内存
	CloseHandle(hProcess);
	FreeModule(Ntdll);
	ExitProcess(0);
	return 0;
}