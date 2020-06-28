function(GetMillerSectionFromInclude destfile definition out)

set(tmp "")
execute_process(COMMAND ${CMAKE_SOURCE_DIR}/batch/millerSectionFromInclude.sh ${destfile} ${definition} OUTPUT_VARIABLE tmp)
if (tmp STREQUAL "")
  unset(${out})
else()
  set(${out} "${tmp}" PARENT_SCOPE)
endif()

endfunction()


function(RemoveGCCFingerprintFromObj targetname)

  foreach(f ${ARGN})
    add_custom_command(TARGET ${targetname} PRE_LINK
      COMMAND ${CMAKE_OBJCOPY} -R '.rdata$$zzz' "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${targetname}.dir/${f}.obj"
      DEPENDS ${targetname}
    )
  endforeach(f)

endfunction()


function(RemoveFingerprints targetname)

set(tmp_stmp "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/.${targetname}_no-fingerprints")
add_custom_command(OUTPUT ${tmp_stmp}
  # .edata && .idata is elementary for windows' LoadLibrary(...) func :/
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold "RemoveFingerprints for ${targetname}"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/removeGccVersion.py "$<TARGET_FILE:${targetname}>"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/nullDataDirs.py "$<TARGET_FILE:${targetname}>"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/removeDosStub.py "$<TARGET_FILE:${targetname}>"
  COMMAND ${CMAKE_COMMAND} -E touch ${tmp_stmp}
  DEPENDS ${targetname}
)
add_custom_target(${targetname}_no-fingerprints ALL DEPENDS ${targetname} ${tmp_stmp})

endfunction()


function(CreateBinary targetname outfile)

set(tmp_stmp "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/.${targetname}_bin-build")
add_custom_command(OUTPUT ${outfile} ${tmp_stmp}
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold "CreateBinary: ${outfile}"
  COMMAND ${CMAKE_COMMAND} -E remove ${tmp_stmp}
  COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${targetname}>" "${outfile}"
  COMMAND ${CMAKE_STRIP} -R .edata "${outfile}" || true
  COMMAND ${CMAKE_STRIP} -R .idata "${outfile}" || true
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/removeGccVersion.py "${outfile}"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/nullDataDirs.py "${outfile}"
  COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/batch/removeDosStub.py "${outfile}"
  COMMAND chmod -x "${outfile}"
  COMMAND ${CMAKE_COMMAND} -E touch ${tmp_stmp}
  DEPENDS ${targetname}
)
add_custom_target(${targetname}_bin ALL DEPENDS ${targetname} ${outfile} ${tmp_stmp})

endfunction()


function(PrefixPath var prefix)

  set(listVar "")
  foreach(f ${ARGN})
    list(APPEND listVar "${prefix}/${f}")
  endforeach(f)
  set(${var} "${listVar}" PARENT_SCOPE)

endfunction()


include(CheckCSourceCompiles)

function(CompileCSource source result cflags defs incl libs quiet)
  set(CMAKE_REQUIRED_FLAGS ${cflags})
  set(CMAKE_REQUIRED_DEFINITIONS ${defs})
  set(CMAKE_REQUIRED_INCLUDES ${incl})
  set(CMAKE_REQUIRED_LIBRARIES ${libs})
  set(CMAKE_REQUIRED_QUIET ${quiet})
  CHECK_C_SOURCE_COMPILES("${source}" ${result})
endfunction()

function(CloneGitSubmodule path)
  find_package(Git QUIET)
  option(GIT_SUBMODULE "Clone git submodules during build" ON)
  if(GIT_SUBMODULE)
    message(STATUS "Git Submodule update: ${GIT_EXECUTABLE} submodule update --init --recursive -- ${path}")
    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- "${path}"
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    RESULT_VARIABLE GIT_SUBMOD_RESULT
                    ERROR_QUIET OUTPUT_QUIET)
    if(NOT GIT_SUBMOD_RESULT EQUAL "0")
      message(FATAL_ERROR "Git Submodule update failed with ${GIT_SUBMOD_RESULT}.")
    endif()
  endif()
endfunction()
