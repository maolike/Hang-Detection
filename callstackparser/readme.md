# callstackparser

Download pdb, parse the call stack in %temp%hangs.log, and generate a file named "hang-uuid"; `uuid` corresponds to the json field in hangs.log

## Require

1. Corresponding symbol server,eg:https://msdl.microsoft.com/download/symbols
2. Then modify global variables `symbolServers` in main.cpp.

## Build

`configure.bat`

`build.bat`

## Output

bin\Release

## Usage

1. Delete all files except exe in the bin directory (previously downloaded pdb, etc.)
2. run exe file
