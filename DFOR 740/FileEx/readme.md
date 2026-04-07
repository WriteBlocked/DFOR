# FileEx
This tool recreates the functionality of dir/ls, pwd, and cd.

This tool was made by Hiller Hoover for the midterm of the DFOR 740 in the Spring 2026 semester at George Mason University.

## Usage
```
FileEx.exe 
FileEx.exe [DIRECTORY] [FLAG]
FileEx.exe [FLAG]
```

### Flags:

| Flag            | Description                                                                                                                                                                        |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| /?              | prints a help menu and exits.                                                                                                                                                      |
| /cd [DIRECTORY] | When supplied a directory, prints the contents of that directory. Without a directory, will print the current folder. You can also provide it relative paths like .. and .\somedir |
| /q              | When provided a directory, will list the owners of all files in that directory. You can provide a directory and this flag will show the owners of files in that directory.         |
| /a              | Shows hidden files in a provided directory. Without a directory provided, will print all files, including files with the hidden attribute, in the current directory.               |
| /s              | Shows files in directories recursively for a given directory. When not provided with a directory, it will show the recursive contents of directories in the current path.          |

It is designed to be used on a Windows x64-86 machine. 
This folder contains the source code, compiled executable, and a set of sysmon rules to detect the usage of this tool.

Running FileEx with no flags with print the current directory (that the tool is in or the terminal is in?)

The /q flag will show file owners
The /a flag will show hidden files
The /s flag will show a recursive listing.