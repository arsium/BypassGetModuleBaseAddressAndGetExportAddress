# Bypass GetModuleBaseAddress and GetExportAddress in C#
## A proof of concept of real and native custom GetExportAddress (GetProcAddress) and GetModuleBaseAddress (GetModuleHandle) in C#.

This took me so long time to code and find resources about it (mostly old and not working anymore or C++). I decided to write that in C# because I've never seen REAL implementation of those functions. Also most of native imports I wrote come from ReactOS code I translated to C# and then tested with ProcessHacker for PEB and Detect It Easy for Image structures.
<br>
Works with x86 and x64.
<br>
## TODO 
* Some code refractoring & improvements
* Some docs or explanations
