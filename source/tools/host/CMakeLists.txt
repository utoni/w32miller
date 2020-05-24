cmake_minimum_required(VERSION 2.8)
set(SYSROOT_DIR ../../../deps/sysroot/bin)
set(TOOLCHAIN_PREFIX ${CMAKE_SOURCE_DIR}/${SYSROOT_DIR})
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}/gcc)
set(CMAKE_LINKER ${TOOLCHAIN_PREFIX}/ld)
set(CMAKE_CXX_COMPILER false)
set(CMAKE_CXX_LINK_EXECUTABLE false)
set(CMAKE_RC_COMPILER_INIT false)
project(host-tools C)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_RULE_MESSAGES OFF)

set(CMAKE_C_FLAGS "-Wall -std=gnu99 -g -D_GNU_SOURCE=1 -D_NO_COMPAT=1 -D_NO_UTILS=1 -D_HOST_TOOLS=1")

set(MILLER_DEFAULT_SRCDIR ${CMAKE_SOURCE_DIR}/../.. CACHE INTERNAL "" FORCE)
set(MILLER_DEFAULT_HDRDIR ${CMAKE_SOURCE_DIR}/../../../include CACHE INTERNAL "" FORCE)
set(MILLER_DEFAULT_TOOLSDIR ${CMAKE_SOURCE_DIR}/.. CACHE INTERNAL "" FORCE)

message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_LINKER: ${CMAKE_LINKER}")
message(STATUS "CMAKE_C_LINK_EXECUTABLE: ${CMAKE_C_LINK_EXECUTABLE}")

if (NOT MILLER_SRCDIR)
  message(AUTHOR_WARNING "MILLER_SRCDIR: missing, using default ${MILLER_DEFAULT_SRCDIR}")
  set(MILLER_SRCDIR ${MILLER_DEFAULT_SRCDIR})
else()
  message(STATUS "MILLER_SRCDIR: ${MILLER_SRCDIR}")
endif()

if (NOT MILLER_TOOLSDIR)
  message(AUTHOR_WARNING "MILLER_TOOLSDIR: missing")
  set(MILLER_TOOLSDIR ${MILLER_DEFAULT_TOOLSDIR})
else()
  message(STATUS "MILLER_TOOLSDIR: ${MILLER_TOOLSDIR}")
endif()

if (NOT MILLER_HDRDIR)
  message(AUTHOR_WARNING "MILLER_HDRDIR: missing")
  set(MILLER_HDRDIR ${MILLER_DEFAULT_HDRDIR})
else()
  message(STATUS "MILLER_HDRDIR: ${MILLER_HDRDIR}")
endif()

if (NOT MILLER_HDRDIR_CREATED)
  message(FATAL_ERROR "MILLER_HDRDIR_CREATED: missing")
endif()

if (NOT LOADER_ENDMARKER)
  message(FATAL_ERROR "LOADER_ENDMARKER: missing")
else()
  message(STATUS "LOADER_ENDMARKER: ${LOADER_ENDMARKER}")
endif()

if (NOT PYTHON_INCDIR)
  message(FATAL_ERROR "PYTHON_INCDIR: missing")
else()
  message(STATUS "PYTHON_INCDIR: ${PYTHON_INCDIR}")
endif()

message(STATUS "INSTALL_DEST: ${INSTALL_DEST}")


set(CRYPT_SRC ${MILLER_SRCDIR}/aes.c ${MILLER_SRCDIR}/crypt.c ${MILLER_SRCDIR}/utils.c hdr_crypt.c)
set(STRINGS_SRC ${MILLER_SRCDIR}/crypt_strings.c ${MILLER_SRCDIR}/crypt.c ${MILLER_SRCDIR}/utils.c ${MILLER_TOOLSDIR}/helper.c)


add_executable(hdr_crypt-host ${CRYPT_SRC})
target_include_directories(hdr_crypt-host PRIVATE ${MILLER_HDRDIR} ${MILLER_TOOLSDIR})


add_executable(strings-host ${STRINGS_SRC})
target_include_directories(strings-host PRIVATE ${MILLER_HDRDIR} ${MILLER_HDRDIR_CREATED} ${MILLER_TOOLSDIR})
target_compile_definitions(strings-host PRIVATE _PRE_RELEASE=1 _STRINGS_BIN=1)


add_library(pyloader SHARED ${MILLER_TOOLSDIR}/helper.c pyloader.c)
target_include_directories(pyloader PRIVATE ${PYTHON_INCDIR} ${MILLER_HDRDIR} ${MILLER_TOOLSDIR})
target_compile_definitions(pyloader PRIVATE _USE_PYTHON=1 _LOADER_ENDMARKER=${LOADER_ENDMARKER})
set_target_properties(pyloader PROPERTIES PREFIX "")
set_target_properties(pyloader PROPERTIES COMPILE_FLAGS "-fPIC -O2 -shared -Wextra -Wno-unused-parameter")


add_library(pycrypt SHARED ${MILLER_SRCDIR}/utils.c ${MILLER_SRCDIR}/crypt.c ${MILLER_SRCDIR}/aes.c ${MILLER_TOOLSDIR}/helper.c pycrypt.c)
target_include_directories(pycrypt PRIVATE ${PYTHON_INCDIR} ${MILLER_HDRDIR} ${MILLER_TOOLSDIR})
target_compile_definitions(pycrypt PRIVATE _USE_PYTHON=1)
set_target_properties(pycrypt PROPERTIES PREFIX "")
set_target_properties(pycrypt PROPERTIES COMPILE_FLAGS "-fPIC -O2 -shared -Wextra -Wno-unused-parameter -Wno-sign-compare")


macro(host_tools_install target destdir)
  set(${target}_FILE "${destdir}/${target}")

  add_custom_command(OUTPUT ${${target}_FILE} /force-run
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:${target}>" "${${target}_FILE}"
  )
  add_custom_target(${target}-install
    ALL
    DEPENDS ${target} ${${target}_FILE}
  )
  add_dependencies(${target}-install ${target})
endmacro()

host_tools_install(hdr_crypt-host ${INSTALL_DEST})
host_tools_install(pyloader ${INSTALL_DEST})
host_tools_install(pycrypt ${INSTALL_DEST})
host_tools_install(strings-host ${INSTALL_DEST})
