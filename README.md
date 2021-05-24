abstract
========
The project emerged during my studies. <br />
It is a showcase demonstration which covers DLL injection and a (very basic) command&control infrastructure. <br />
However, as I never had the time to finished it (and presumably lost focus), it is still premature. So please see this project as a unstable-as-fuck-example and not as a copy-pasta-ready development framework. <br />
As this project was written by an unexperienced and fault-tolerant student, the code looks ugly w/ limited readability, missing documentation and may crash at any time. <br />
<br />

w32miller
========
An educational malware development kit or my preferable abbreviation: **mdk**. <br />
Only x86 architectures are supported at the moment. Most of the code is written in C, porting it to other architectures isn't wizardry. <br />
The more complex parts are the assembler sources, which are tied to x86. Porting the loader to x64 may cause some headaches. <br />
It's name was derived from [Chaim Miller](https://www.imdb.com/title/tt4591236/), the real Inglourious Basterd. <br />
Why did I choose that name you may ask. Long story - to make it short: I love his attitude! <br />
Used languages: <b>Bash</b>, <b>CMake</b>, <b>ASM-x86</b>, <b>C</b>, <b>Go</b>, <b>Python</b> <br />
<br />

build
========
As my favourite platforms are (Arch|Debian) based, the whole config&build process was designed to work on those platforms. <br />
Other build environments may not produce the desired results. <br />
The following commands should only be run once. <br /><br />
## Pre-Requirements (debian) <br />
`sudo apt-get install g++ gcc autoconf automake flex bison texinfo cmake` <br />
See <b>INSTALL</b> for more information. <br />
<br />
## Build miller toolchain <br />
`./deps/makedeps.sh N` (where N is the number of simultaneous build jobs, default: 1)<br />
It will download/extract/compile basic developer tools (python-2.7.18, nasm-2.12.02, binutils-2.31.1, gcc-8.2.0, mingw-w64-v6.0.0) <br />
The Toolchain build is necessary, because we will probably use a patched gcc in the future. <br />
<b>WARNING</b>: The project may neither compile nor work with other toolchain combinations! <br />
<br />
## Configure project <br />
`cd /path/to/project` <br />
`mkdir build && cd build` <br />
`cmake -DBUILD_ALL_TOOLS=ON -DBUILD_CNCPROXY=ON -DBUILD_TESTS=ON -DEXTRA_VERBOSE=ON -DHTTP_LOCALHOST=ON -DINFECT_DUMMY=ON ..`<br />
<br />
## Build project <br />
`make -jN` (where N is the number of simultaneous build jobs) <br />
<br />
To install all generated binaries use: `make install DESTDIR=[PATH]` <br />
<br />
## Try it! <br />
There are a several ways to tryout this project. <br />
If you want a basic CNC communication you should start the cncproxy first with: `[BUILD_DIR]/host-tools/cncproxy-host` <br />
 1. `cd [BUILD_DIR]/bin`
 2. `wine loader_base.exe` (<b>PART</b> encrypted binary) <br />
 3. <b>OR</b> `wine loader_base_enc.exe` (<b>FULL</b> encrypted binary) <br />
 4. run `wine dummy.exe 120` which should now be infected and try to contact the CNC service <br />

Other intresting executables: <br />
 * `wine runbin.exe libw32miller_pre-shared.dll` <br />
 * `wine runbin.exe libw32miller-shared.dll` <br />
 * `wine runbin.exe bin/w32miller_pre.bin` <br />
 * `wine runbin.exe bin/w32miller.bin` <br />
<br />

Test Windows Portable Executable compliance: <br />
 * `wine loadmodule.exe bin/libw32miller_pre-shared.dll` <br />
 * `wine loadmodule.exe bin/libw32miller-shared.dll` <br />

UNIT tests: <br />
 * `wine tests.exe` <br />
<br />
Or use a virtual machine and run it there. (e.g. VirtualBox) <br />
<br />
This is an educational mdk only: It tries to infect <b>one</b> windows pe binary named <b>dummy.exe</b> in your current working directory. <br />
<br />
<b>WARNING</b>: It is highly recommended to use a VM like <b>virtualbox</b>. Otherwise you should install <b>wine</b>. <br />

features
========
 - patched mingw64 toolchain (and build script) <br />
 - tor and patched libtor support <br />
 - minimal x86/x64 disassembler/patcher <br />
 - pe code/data injector <br />
 - command&control communication (http-web2tor / irc-obsolete; replaced by libtor in the future) <br />
 - golang based c&c service <br />
<br />

how it works
========
DLL (infect): <br />

 1. DLL adds loader section to target (default: .minit) <br />
 2. DLL adds own section to target (default: .miller) <br />
 3. DLL sets const data in loader <br />
 4. DLL copies the loader to its section <br />
 5. DLL copies itself to its very own section <br />
 6. DLL injects FAR JUMP somewhere near the EntryPoint RVA and set the operand to the loader VA <br />

<br />
An infected file: <br />

 1. somewhere near the Address of EntryPoint RVA it calls the loader entry address <br />

<br />
LOADER: <br />

 1. decrypt strings <br />
 2. get some function pointers/data <br />
 3. copy encrypted DLL section to temporary allocated buffer <br />
 4. decrypt DLL if encrypted and read PE header <br />
 5. allocate memory for image sections <br />
 6. copy sections from (parsed/plain PE file) temp buffer to final destinations <br />
 7. do fixups if image relocation is necessary <br />
 8. jump to the CRT <br />

<br />
CRT (part of DLL): <br />

 1. does minimal initializing <br />
 2. check if started by loader (and set data/register as needed) <br />
 3. setup function parameter <br />
 4. call real dll entry function _main(...) <br />
 5. start some threads e.g. infection/network thread
 6. cleanup stack <br />
 7. return to the loader <br />

<br />
LOADER: <br />

 9. cleanup and jump back right after where we were injected <br />

<br />

Command'n'Control (<b>CNC</b>)
========
The Go written CNC proxy which acts as man-in-the-middle between an infected binary and CNC master. <br />
CNC proxy does the basic authentication and receives commands from the CNC master. <br />
Keep in mind that this part of the project is the most ALPHA'ic one. <br />
So the cncmaster does not do anything useful at the moment. <br />
For a very basic test, the cncproxy is sufficient. <br />
<br />

Documentation (lacking)
========
![Basic App Architecture](/doc/apps.png)
