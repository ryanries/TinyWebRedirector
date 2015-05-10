// TinyWebRedirector
// Joseph Ryan Ries, 2015
// Vista/2008 and above.
// Warning - This code is not portable to non-Unicode builds.

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <AclAPI.h> // includes windows.h, among others.
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERVICE_NAME      L"TinyWebRedirector"
#define SERVICE_VERSION   L"1.0"
#define SERVICE_DESC      L"Simply listens for and redirects HTTP requests. Configurable via registry in HKLM\\SYSTEM\\CurrentControlSet\\Services\\"SERVICE_NAME
#define EVENTLOG_REG_PATH L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\"SERVICE_NAME
#define SERVICE_REG_PATH  L"SYSTEM\\CurrentControlSet\\Services\\"SERVICE_NAME
#define MAX_EVENT_CHARS	  1024

wchar_t          g_EventBuffer[MAX_EVENT_CHARS];
wchar_t*         g_EventText[1] = { g_EventBuffer };
CRITICAL_SECTION g_EventCritSec;

SERVICE_STATUS        g_ServiceStatus;
SERVICE_STATUS_HANDLE g_StatusHandle;
HANDLE				  g_ServiceStopEvent;
HANDLE                g_EventLogHandle;
HANDLE                g_WorkerThreadHandle;

DWORD   g_Port;
wchar_t g_URL[256];

HRESULT WriteEventW(_In_ WORD EventType, _In_ DWORD EventId, _In_ const wchar_t* EventText, _In_ ...)
{
	EnterCriticalSection(&g_EventCritSec);
	wchar_t FormattedEventText[MAX_EVENT_CHARS] = { 0 };
	va_list ArgPointer = NULL;

	if (wcslen(EventText) > (sizeof(g_EventBuffer) / sizeof(wchar_t)) - sizeof(wchar_t))
	{
		LeaveCriticalSection(&g_EventCritSec);
		return E_INVALIDARG;
	}

	if (g_EventLogHandle == NULL)
	{
		LeaveCriticalSection(&g_EventCritSec);
		return E_HANDLE;
	}

	DWORD Result = 0;

	va_start(ArgPointer, EventText);
	Result = _vsnwprintf_s(FormattedEventText, MAX_EVENT_CHARS - sizeof(wchar_t), EventText, ArgPointer);
	va_end(ArgPointer);

	if (Result < 0)
	{
		LeaveCriticalSection(&g_EventCritSec);
		return E_FAIL;
	}

	wcscpy_s(g_EventBuffer, FormattedEventText);
	
	Result = ReportEvent(g_EventLogHandle, EventType, 0, EventId, NULL, 1, 0, (LPCWSTR*)g_EventText, 0);
	LeaveCriticalSection(&g_EventCritSec);

	if (Result == 0)
	{
		return E_FAIL;
	}
	else
	{
		return ERROR_SUCCESS;
	}
}

void PrintUsage()
{
	wprintf(L"\n%s v%s - Redirects HTTP Requests\n", SERVICE_NAME, SERVICE_VERSION);
	wprintf(L"Copyright (C) 2015 Joseph Ryan Ries\n");
	wprintf(L"www.myotherpcisacloud.com\n\n");
	wprintf(L"Usage:\n");
	wprintf(L"Install:   %s -install\n", SERVICE_NAME);
	wprintf(L"Uninstall: %s -uninstall\n\n", SERVICE_NAME);
}

const wchar_t* ErrorCodeToStringW(_In_ DWORD ErrorCode)
{
	if (ErrorCode == NO_ERROR)
	{
		return L"NONE";
	}

	static wchar_t ErrorString[256] = { 0 };

	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ErrorString, 255, NULL);

	return ErrorString;
}

// NOTE(Ryan): This function returns true if the string ends with the specified Suffix/substring.
// Uses wide characters. Case sensitive.
int StringEndsWithW(_In_opt_ const wchar_t* String, _In_opt_ const wchar_t* Suffix)
{
	if (String == NULL || Suffix == NULL)
	{
		return 0;
	}

	size_t StringLength = wcslen(String);
	size_t SuffixLength = wcslen(Suffix);

	if (SuffixLength > StringLength)
	{
		return 0;
	}

	return 0 == wcsncmp(String + StringLength - SuffixLength, Suffix, SuffixLength);
}

BOOL FileExists(_In_ LPCWSTR FilePath)
{
	DWORD FileAttributes = GetFileAttributes(FilePath);
	return (FileAttributes != INVALID_FILE_ATTRIBUTES && !(FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

DWORD AddAceToObjectSecurityDescriptor(LPTSTR ObjectName, SE_OBJECT_TYPE ObjectType, LPTSTR Trustee, TRUSTEE_FORM TrusteeForm, DWORD AccessRights, ACCESS_MODE AccessMode, DWORD Inheritance)
{
	DWORD Result = 0;
	PACL OldDACL = NULL;
	PACL NewDACL = NULL;
	PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
	EXPLICIT_ACCESS ExplicitAccess;

	if (NULL == ObjectName)
	{
		return ERROR_INVALID_PARAMETER;
	}

	// Get a pointer to the existing DACL.
	Result = GetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &OldDACL, NULL, &SecurityDescriptor);
	if (ERROR_SUCCESS != Result)
	{
		wprintf(L"GetNamedSecurityInfo Error 0x%x %s\n", Result, ErrorCodeToStringW(Result));
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE. 

	ZeroMemory(&ExplicitAccess, sizeof(EXPLICIT_ACCESS));
	ExplicitAccess.grfAccessPermissions = AccessRights;
	ExplicitAccess.grfAccessMode        = AccessMode;
	ExplicitAccess.grfInheritance       = Inheritance;
	ExplicitAccess.Trustee.TrusteeForm  = TrusteeForm;
	ExplicitAccess.Trustee.ptstrName    = Trustee;

	// Create a new ACL that merges the new ACE
	// into the existing DACL.

	Result = SetEntriesInAcl(1, &ExplicitAccess, OldDACL, &NewDACL);
	if (ERROR_SUCCESS != Result)  
	{
		wprintf(L"SetEntriesInAcl Error 0x%x %s\n", Result, ErrorCodeToStringW(Result));
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.

	Result = SetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, NewDACL, NULL);
	if (ERROR_SUCCESS != Result)
	{
		wprintf(L"SetNamedSecurityInfo Error 0x%x %s\n", Result, ErrorCodeToStringW(Result));
		goto Cleanup;
	}

Cleanup:

	if (SecurityDescriptor != NULL)
	{
		LocalFree((HLOCAL)SecurityDescriptor);
	}
	if (NewDACL != NULL)
	{
		LocalFree((HLOCAL)NewDACL);
	}
	//if (OldDACL != NULL)
	//{
	//	LocalFree((HLOCAL)OldDACL);
	//}

	return Result;
}

void InstallService()
{	
	wchar_t PathToEventCreate[MAX_PATH] = { 0 };

	DWORD EnvironmentVarLength = 0;

	EnvironmentVarLength = GetEnvironmentVariable(L"SystemRoot", PathToEventCreate, MAX_PATH);

	if (EnvironmentVarLength != 0 && (GetLastError() != ERROR_ENVVAR_NOT_FOUND) && (EnvironmentVarLength < MAX_PATH))
	{
		if (!StringEndsWithW(PathToEventCreate, L"\\"))
		{
			wcscat_s(PathToEventCreate, L"\\");
		}
	}
	else
	{
		wprintf(L"ERROR: Failed to locate the SystemRoot environment variable!\n");
		return;
	}

	wcscat_s(PathToEventCreate, L"System32\\Eventcreate.exe");

	if (!FileExists(PathToEventCreate))
	{
		wprintf(L"ERROR: %s not found!\n", PathToEventCreate);
		return;
	}

	HKEY EventLogKeyHandle = NULL;
	LONG LResult = 0;

	LResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, EVENTLOG_REG_PATH, 0, KEY_READ, &EventLogKeyHandle);
	
	if (LResult != ERROR_FILE_NOT_FOUND)
	{
		wprintf(L"ERROR: It appears the service is already installed. Uninstall first then try again.\n");
		return;
	}

	LResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE, EVENTLOG_REG_PATH, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &EventLogKeyHandle, NULL);

	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to create registry key! (Check Admin privileges.) Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	DWORD Value = 1;
	LResult = RegSetValueEx(EventLogKeyHandle, L"CustomSource", 0, REG_DWORD, (const BYTE*)&Value, sizeof(DWORD));
	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to set registry value! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	Value = 7;
	LResult = RegSetValueEx(EventLogKeyHandle, L"TypesSupported", 0, REG_DWORD, (const BYTE*)&Value, sizeof(DWORD));
	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to set registry value! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	LResult = RegSetValueEx(EventLogKeyHandle, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE*)&PathToEventCreate, (DWORD)(wcslen(PathToEventCreate) * sizeof(wchar_t)));
	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to set registry value! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	if (EventLogKeyHandle)
	{
		RegCloseKey(EventLogKeyHandle);
	}

	wprintf(L"Eventlog source registered.\n");


	SC_HANDLE ServiceController = NULL;
	SC_HANDLE MyService = NULL;

	ServiceController = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (ServiceController == NULL)
	{
		wprintf(L"ERROR: Failed to open Service Controller! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	wchar_t ImageFilePath[MAX_PATH] = { 0 };

	DWORD PathLength = 0;
	PathLength = GetModuleFileName(NULL, ImageFilePath, MAX_PATH);
	if (PathLength != 0 && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
	{
		MyService = CreateService(
			ServiceController,
			SERVICE_NAME,
			SERVICE_NAME,
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			(LPCWSTR)ImageFilePath,
			NULL,
			NULL,
			NULL,
			L"NT AUTHORITY\\LocalService",
			NULL);
	}

	if (MyService == NULL)
	{
		wprintf(L"ERROR: Failed to create service! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	SERVICE_DESCRIPTION ServiceDescription = { SERVICE_DESC };

	if (ChangeServiceConfig2(MyService, SERVICE_CONFIG_DESCRIPTION, &ServiceDescription) == 0)
	{
		wprintf(L"ERROR: Failed to set service description! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	SERVICE_DELAYED_AUTO_START_INFO AutoStartInfo = { 0 };

	AutoStartInfo.fDelayedAutostart = TRUE;

	if (ChangeServiceConfig2(MyService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &AutoStartInfo) == 0)
	{
		wprintf(L"ERROR: Failed to set service to delayed auto start! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	wprintf(L"%s service installed.\n", SERVICE_NAME);

	// Need to make sure 'Local Service' has read permissions to the executable image.
	DWORD AddACEResult = AddAceToObjectSecurityDescriptor(ImageFilePath, SE_FILE_OBJECT, L"NT AUTHORITY\\LocalService", TRUSTEE_IS_NAME, GENERIC_READ | GENERIC_EXECUTE, GRANT_ACCESS, NO_INHERITANCE);
	if (AddACEResult != ERROR_SUCCESS)
	{
		wprintf(L"WARNING: Failed to set read access on the executable! Code: 0x%x %s\n", AddACEResult, ErrorCodeToStringW(AddACEResult));
	}

	HKEY ServiceRegKey = NULL;

	LResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SERVICE_REG_PATH, 0, KEY_ALL_ACCESS, &ServiceRegKey);

	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to open service registry key! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	Value = 80;
	LResult = RegSetValueEx(ServiceRegKey, L"Port", 0, REG_DWORD, (const BYTE*)&Value, sizeof(DWORD));
	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to set registry value! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}	

	wchar_t RedirectURL[] = L"www.myotherpcisacloud.com";

	LResult = RegSetValueEx(ServiceRegKey, L"RedirectURL", 0, REG_SZ, (const BYTE*)&RedirectURL, (DWORD)(wcslen(RedirectURL) * sizeof(wchar_t) + 1));

	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to set registry value! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	if (ServiceRegKey)
	{
		RegCloseKey(ServiceRegKey);
	}

	if (StartService(MyService, 0, NULL) == 0)
	{
		wprintf(L"WARNING: StartService failed! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
	}

	if (ServiceController)
	{
		CloseServiceHandle(ServiceController);
	}

	wprintf(L"\nYou may choose to customize the port number and URL in the registry:\n");
	wprintf(L"HKLM\\%s\n", SERVICE_REG_PATH);
	wprintf(L"Restart the service for changes to take effect.\n");
}

void UninstallService()
{
	SC_HANDLE ServiceController = NULL;
	SC_HANDLE MyService = NULL;

	ServiceController = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (ServiceController == NULL)
	{
		wprintf(L"ERROR: Failed to open Service Controller! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	MyService = OpenService(ServiceController, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (MyService == NULL)
	{
		wprintf(L"ERROR: Failed to open handle to service! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		goto DeleteEventLogRegistryKey;
	}

	wprintf(L"Waiting for service to stop...\n");

	SERVICE_STATUS_PROCESS ServiceStatus;
	DWORD StopTimeout = 0;
	DWORD BytesNeeded = 0;

	ControlService(MyService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatus);

	while (ServiceStatus.dwCurrentState != SERVICE_STOPPED && StopTimeout < 6)
	{
		Sleep(4000);
		StopTimeout++;
		if (QueryServiceStatusEx(MyService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatus, sizeof(SERVICE_STATUS_PROCESS), &BytesNeeded) == 0)
		{
			wprintf(L"ERROR: QueryServiceStatusEx failed! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		}
	}

	if (StopTimeout >= 6)
	{
		wprintf(L"WARNING: Service did not stop in a timely manner.\n");
	}

	if (DeleteService(MyService) == 0)
	{
		wprintf(L"ERROR: Failed to delete service! Code: 0x%x %s\n", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}
	else
	{
		wprintf(L"Service uninstalled.\n");
	}

DeleteEventLogRegistryKey:

	if (ServiceController)
	{
		CloseServiceHandle(ServiceController);
	}

	HKEY EventLogKeyHandle = NULL;
	LONG LResult = 0;

	LResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\", 0, KEY_ALL_ACCESS, &EventLogKeyHandle);

	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Failed to open eventlog registry key. Check admin privileges. Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
		return;
	}

	LResult = RegDeleteTree(EventLogKeyHandle, SERVICE_NAME);

	if (LResult != ERROR_SUCCESS)
	{
		wprintf(L"WARNING: Failed to delete eventlog registry key! Code: 0x%x %s\n", LResult, ErrorCodeToStringW(LResult));
	}
	else
	{
		wprintf(L"Eventlog registry key deleted.\n");
	}
}

DWORD WINAPI ServiceWorkerThread(_In_ LPVOID)
{
	WSADATA WinsockData = { 0 };
	
	if (WSAStartup(MAKEWORD(2, 2), &WinsockData) != 0)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 108, L"ServiceWorkerThread: Failed to initialize Winsock! Code: 0x%x %s", WSAGetLastError(), ErrorCodeToStringW(WSAGetLastError()));
		return WSAGetLastError();
	}

	SOCKET ServerSocket = { 0 };

	if ((ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 109, L"ServiceWorkerThread: Failed to create socket! Code: 0x%x %s", WSAGetLastError(), ErrorCodeToStringW(WSAGetLastError()));
		return WSAGetLastError();
	}

	struct sockaddr_in Server;

	Server.sin_family = AF_INET;
	Server.sin_addr.s_addr = INADDR_ANY;
	Server.sin_port = htons((u_short)g_Port);

	if (bind(ServerSocket, (struct sockaddr *)&Server, sizeof(Server)) == SOCKET_ERROR)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 110, L"ServiceWorkerThread: Failed to bind to port %d! Code: 0x%x %s", g_Port, WSAGetLastError(), ErrorCodeToStringW(WSAGetLastError()));
		return WSAGetLastError();
	}

	listen(ServerSocket, 3);

	int AddressLength = sizeof(struct sockaddr_in);

	SOCKET ClientSocket = { 0 };

	struct sockaddr_in Client;

	char UnicodeURLtoASCII[128] = { 0 };

	size_t CharactersConverted = 0;
	wcstombs_s(&CharactersConverted, UnicodeURLtoASCII, g_URL, wcslen(g_URL));

	while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
	{
		int Result = 0;
		char ReceiveBuffer[512] = { 0 };

		ClientSocket = accept(ServerSocket, (struct sockaddr *)&Client, &AddressLength);
		Result = recv(ClientSocket, ReceiveBuffer, sizeof(ReceiveBuffer), 0);

		char Response[512] = { 0 };
		char HTML[512] = { 0 };

		_snprintf_s(
			HTML, 
			sizeof(HTML), 
			"<html><head><meta http-equiv=\"refresh\" content=\"0; url=http://%s\"/></head><body>Click <a href=\"%s\">here</a> if you are not automatically redirected.</body></html>",
			UnicodeURLtoASCII,
			UnicodeURLtoASCII);

		_snprintf_s(
			Response, 
			sizeof(Response), 
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", 
			(int)strlen(HTML),
			HTML);

		send(ClientSocket, Response, (int)strlen(Response), 0);
		
		shutdown(ClientSocket, SD_SEND);
		closesocket(ClientSocket);	
	}

	closesocket(ServerSocket);

	return ERROR_SUCCESS;
}

VOID WINAPI ServiceControlHandler(_In_ DWORD ControlCode)
{
	switch (ControlCode)
	{
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
		{
			if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
			{
				break;
			}

			WSACleanup();

			if (TerminateThread(g_WorkerThreadHandle, 0) == 0)
			{
				WriteEventW(EVENTLOG_ERROR_TYPE, 120, L"WARNING: TerminateThread failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
			}

			// Send yourself a "kill signal" to keep the service from blocking so it will stop
			//SOCKET ClientSocket = { 0 };
			//struct sockaddr_in Server;

			//if ((ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			//{
			//	WriteEventW(EVENTLOG_ERROR_TYPE, 115, L"ServiceControlHandler: Failed to create socket for kill signal! Code: 0x%x %s", g_Port, WSAGetLastError(), ErrorCodeToStringW(WSAGetLastError()));
			//}

			//InetPton(AF_INET, L"127.0.0.1", &Server.sin_addr.s_addr);
			//Server.sin_family = AF_INET;
			//Server.sin_port = htons((u_short)g_Port);

			//if (connect(ClientSocket, (struct sockaddr *)&Server, sizeof(Server)) < 0)
			//{
			//	WriteEventW(EVENTLOG_ERROR_TYPE, 116, L"ServiceControlHandler: Failed to connect to send kill signal! Code: 0x%x %s", g_Port, WSAGetLastError(), ErrorCodeToStringW(WSAGetLastError()));
			//}
			//else
			//{
			//	char Kill[5] = "kill";
			//	send(ClientSocket, Kill, (int)strlen(Kill), 0);
			//	closesocket(ClientSocket);
			//}

			g_ServiceStatus.dwControlsAccepted = 0;
			g_ServiceStatus.dwCurrentState     = SERVICE_STOP_PENDING;
			g_ServiceStatus.dwWin32ExitCode    = 0;
			g_ServiceStatus.dwCheckPoint       = 4;

			if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
			{
				WriteEventW(EVENTLOG_ERROR_TYPE, 107, L"ServiceControlHandler: SetServiceStatus (STOP_PENDING) failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
			}

			SetEvent(g_ServiceStopEvent);
			break;
		}		
		default:
		{
			break;
		}
	}
}

VOID WINAPI ServiceMain(_In_ DWORD, _In_ LPTSTR*)
{
	g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceControlHandler);
	if (g_StatusHandle == NULL)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 101, L"ServiceMain: RegisterServiceCtrlHandler failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));

	g_ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
	g_ServiceStatus.dwControlsAccepted        = NULL;
	g_ServiceStatus.dwWin32ExitCode           = NO_ERROR;
	g_ServiceStatus.dwServiceSpecificExitCode = NO_ERROR;
	g_ServiceStatus.dwWaitHint                = 5000;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == NULL)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 102, L"ServiceMain: SetServiceStatus (PENDING) failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_ServiceStopEvent == NULL)
	{
		g_ServiceStatus.dwControlsAccepted = NULL;
		g_ServiceStatus.dwCurrentState     = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode    = GetLastError();
		g_ServiceStatus.dwCheckPoint       = 1;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		WriteEventW(EVENTLOG_ERROR_TYPE, 103, L"ServiceMain: Failed to create stop event! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	g_ServiceStatus.dwCurrentState     = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode    = NO_ERROR;
	g_ServiceStatus.dwCheckPoint       = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 104, L"ServiceMain: SetServiceStatus (RUNNING) failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	g_WorkerThreadHandle = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

	if (g_WorkerThreadHandle == NULL)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 105, L"ServiceMain: CreateThread failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return;
	}

	WaitForSingleObject(g_WorkerThreadHandle, INFINITE);

	WriteEventW(EVENTLOG_INFORMATION_TYPE, 302, L"ServiceMain: Service is stopping.");

	CloseHandle(g_ServiceStopEvent);
	
	g_ServiceStatus.dwControlsAccepted = NULL;
	g_ServiceStatus.dwCurrentState     = SERVICE_STOPPED;
	g_ServiceStatus.dwWin32ExitCode    = NO_ERROR;
	g_ServiceStatus.dwCheckPoint       = 3;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 106, L"ServiceMain: SetServiceStatus (STOPPED) failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
	}
}

// Program entry point.
int wmain(_In_ int argc, _In_ wchar_t* argv[])
{
	if (argc > 2)
	{
		PrintUsage();
		return(0);
	}

	if (argc > 1)
	{
		if (_wcsicmp(argv[1], L"-install") == 0)
		{
			InstallService();
			return(0);
		}
		else if (_wcsicmp(argv[1], L"-uninstall") == 0)
		{
			UninstallService();
			return(0);
		}
		else
		{
			PrintUsage();
			return(0);
		}
	}

	g_EventLogHandle = RegisterEventSource(NULL, SERVICE_NAME);
	if (g_EventLogHandle == NULL)
	{
		OutputDebugString(L"RegisterEventSource failed!\n");
		return(0);
	}

	InitializeCriticalSection(&g_EventCritSec);

	WriteEventW(EVENTLOG_INFORMATION_TYPE, 300, L"%s v%s service is starting.", SERVICE_NAME, SERVICE_VERSION);

	HKEY ServiceRegKey = NULL;
	LONG LResult = 0;
	DWORD RegBuffer = sizeof(DWORD);

	LResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SERVICE_REG_PATH, 0, KEY_READ, &ServiceRegKey);

	if (LResult != ERROR_SUCCESS)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 111, L"wmain: RegOpenKeyEx failed! Code: 0x%x %s", LResult, ErrorCodeToStringW(LResult));
		return(0);
	}

	LResult = RegQueryValueEx(ServiceRegKey, L"Port", NULL, NULL, (LPBYTE)&g_Port, &RegBuffer);

	if (LResult != ERROR_SUCCESS)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 112, L"wmain: RegQueryValueEx failed! Code: 0x%x %s", LResult, ErrorCodeToStringW(LResult));
		return(0);
	}

	RegBuffer = sizeof(g_URL);	
	LResult = RegQueryValueEx(ServiceRegKey, L"RedirectURL", NULL, NULL, (LPBYTE)&g_URL, &RegBuffer);

	if (LResult != ERROR_SUCCESS)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 113, L"wmain: RegQueryValueEx failed! Code: 0x%x %s", LResult, ErrorCodeToStringW(LResult));
		return(0);
	}


	if (ServiceRegKey)
	{
		RegCloseKey(ServiceRegKey);
	}

	if (g_Port < 1 || g_Port > 65535)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 114, L"Port number in registry was out of range!");
		return(0);
	}

	WriteEventW(EVENTLOG_INFORMATION_TYPE, 303, L"Redirect URL: %s\nPort: %d", g_URL, g_Port);

	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{ SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};	

	if (StartServiceCtrlDispatcher(ServiceTable) == 0)
	{
		WriteEventW(EVENTLOG_ERROR_TYPE, 115, L"wmain: StartServiceCtrlDispatcher failed! Code: 0x%x %s", GetLastError(), ErrorCodeToStringW(GetLastError()));
		return GetLastError();
	}

	if (g_EventLogHandle)
	{
		DeregisterEventSource(g_EventLogHandle);
	}
	return(0);
}