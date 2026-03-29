/*
This code was written by Hiller Hoover for DFOR 740 in the Spring 2026 semester of the DFOR program at GMU.
This program is not malicious, can show the current directory, hidden files, file owners, and change directories.
Due to the inclusion of filesystem, it requires C++ 17 or greater.

For more samples of my work, please visit my GitHub profile at https://github.com/WriteBlocked or my website at https://hhoover.net
*/

#include <windows.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <Aclapi.h>

using namespace std;
namespace fs = std::filesystem;

void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

string FormatSize(ULONGLONG size) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int i = 0;
    double s = (double)size;

    while (s >= 1024 && i < 4) {
        s /= 1024;
        i++;
    }

    char buffer[50];
    sprintf_s(buffer, "%.2f %s", s, units[i]);
    return string(buffer);
}

// Convert FILETIME to readable string
string FileTimeToString(const FILETIME& ft) {
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    char buffer[100];
    sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    return string(buffer);
}

// Get file owner (for /q)
string GetFileOwner(const string& path) {
    PSID ownerSid = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;

    if (GetNamedSecurityInfoA(
        path.c_str(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &ownerSid,
        NULL, NULL, NULL,
        &sd) != ERROR_SUCCESS) {
        return "UNKNOWN";
    }

    char name[256], domain[256];
    DWORD nameSize = 256, domainSize = 256;
    SID_NAME_USE sidType;

    if (LookupAccountSidA(NULL, ownerSid, name, &nameSize, domain, &domainSize, &sidType)) {
        LocalFree(sd);
        return string(domain) + "\\" + string(name);
    }

    LocalFree(sd);
    return "UNKNOWN";
}

// Print file info
void PrintFile(const WIN32_FIND_DATAA& data, const string& fullPath, bool showOwner) {
    bool isDir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    bool isHidden = (data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN);

    string timeStr = FileTimeToString(data.ftCreationTime);

    cout << timeStr << "  ";

    // COLOR LOGIC
    if (isDir) SetColor(11);            // Cyan
    else if (isHidden) SetColor(8);     // Gray
    else SetColor(7);                  // Default

    if (isDir) {
        cout << "<DIR>      ";
    }
    else {
        ULONGLONG size = ((ULONGLONG)data.nFileSizeHigh << 32) | data.nFileSizeLow;
        cout << setw(10) << FormatSize(size) << " ";
    }

    if (showOwner) {
        cout << setw(20) << GetFileOwner(fullPath) << " ";
    }

    cout << data.cFileName << endl;

    SetColor(7); // reset
}

// Directory listing
void ListDirectory(const string& path, bool showHidden, bool recursive, bool showOwner) {
    string searchPath = path + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        cerr << "Failed to open directory: " << path << endl;
        return;
    }

    do {
        string name = findData.cFileName;

        if (name == "." || name == "..") continue;

        bool isHidden = (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN);

        if (!showHidden && isHidden) continue;

        string fullPath = path + "\\" + name;

        PrintFile(findData, fullPath, showOwner);

        // Recurse into subdirectories
        if (recursive && (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            cout << "\nDirectory of " << fullPath << "\n";
            ListDirectory(fullPath, showHidden, recursive, showOwner);
        }

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

// Handle cd functionality
void ChangeDirectory(const string& target) {
    if (!SetCurrentDirectoryA(target.c_str())) {
        cerr << "Failed to change directory.\n";
        return;
    }

    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);

    cout << "Current Directory: " << buffer << endl;
}

// Entry point
int main(int argc, char* argv[]) {
    // No args → pwd
    if (argc == 1) {
        char buffer[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, buffer);
        cout << buffer << endl;
        return 0;
    }

    bool showHidden = false;
    bool recursive = false;
    bool showOwner = false;

    string targetPath = "";
    bool didCD = false;

    // Default to current directory
    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);
    targetPath = buffer;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];

        // --- cd as a flag ---
        if (arg == "cd") {
            if (i + 1 >= argc) {
                cerr << "cd requires a path\n";
                return 1;
            }

            string path = argv[i + 1];

            if (!SetCurrentDirectoryA(path.c_str())) {
                cerr << "Failed to change directory.\n";
                return 1;
            }

            GetCurrentDirectoryA(MAX_PATH, buffer);
            targetPath = buffer;

            didCD = true;
            i++; // skip next argument (path)
        }

        // --- flags ---
        else if (arg == "/a") showHidden = true;
        else if (arg == "/s") recursive = true;
        else if (arg == "/q") showOwner = true;

        // --- implicit directory (like earlier behavior) ---
        else if (arg[0] != '/' && fs::exists(arg) && fs::is_directory(arg)) {
            if (!SetCurrentDirectoryA(arg.c_str())) {
                cerr << "Failed to change directory.\n";
                return 1;
            }

            GetCurrentDirectoryA(MAX_PATH, buffer);
            targetPath = buffer;

            didCD = true;
        }
    }

    // If ONLY cd was used, don't list (match real cd behavior)
    if (didCD && argc <= 3) {
        cout << "Current Directory: " << targetPath << endl;
        return 0;
    }

    cout << "Directory of " << targetPath << "\n\n";
    ListDirectory(targetPath, showHidden, recursive, showOwner);

    return 0;
}