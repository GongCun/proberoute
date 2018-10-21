#include <windows.h>
#include <sysinfoapi.h>
#include <fileapi.h>
#include <stdlib.h>
#include <stdio.h>

static BOOL DirectoryExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int main(int argc, char **argv)
{
    char sysdir_name[512];
    int len;

    len = GetSystemDirectory(sysdir_name, 480);	/* be safe */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory (%d)", GetLastError());
        exit(-1);
    }
        
    strcat(sysdir_name, "\\Npcap");
    if (DirectoryExists(sysdir_name))
        printf("%s\n", sysdir_name);
    else {
        sysdir_name[len] = '\0';
        printf("%s\n", sysdir_name);
    }
    
    return 0;
}

