set(DEPS_BUILDSTAMP deps/sysroot/.stamp_build)

add_custom_command(OUTPUT ${DEPS_BUILDSTAMP}
  COMMAND ./deps/makedeps.sh && touch ${DEPS_BUILDSTAMP}
)
add_custom_target(deps
  DEPENDS ${DEPS_BUILDSTAMP}
)
