# hangdetectiontool

A tool that injects `hangdetect.dll` into the target program, so that it can detect hang without modifying the target program code, and writes the call stack of the main thread when hang is detected into `%temp%hangs.log`

## Usage

> launchWithHangdetect.exe [options] [command line]

Description:
When the main thread hangs for more than the set time,
it will capture the call stack and record it in the local `%temp%hangs.log` file.

Options:  
&emsp;&emsp;/t&emsp;&emsp;: block time (default 2000ms)  
&emsp;&emsp;/v&emsp;&emsp;: Verbose, display memory at start.  
&emsp;&emsp;/?&emsp;&emsp;: This help screen.

## example:

> launchWithHangdetect.exe /t:2000 "C:\test.exe"

## Build

1. CMake
2. Visual Studio
3. run `configure.bat`
4. build the vs project

## Output

bin\Release
