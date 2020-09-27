#include<Windows.h>

BOOL WINAPI DllMain(
	HINSTANCE hInstance,
	DWORD dW,
	LPVOID lPvoid
)
{
	switch (dW)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, LPCSTR("process WW"), LPCSTR("process PP"), MB_OK);
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		MessageBox(NULL, LPCSTR("thread WW"), LPCSTR("thread PP"), MB_OK);
		break;
	case DLL_THREAD_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}