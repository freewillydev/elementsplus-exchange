# Also usable before cabal update: cmake -DELEMENTS_CABAL=/path/to/cabal -P this-file.
find_program(ELEMENTS_CABAL cabal REQUIRED)
execute_process(COMMAND "${ELEMENTS_CABAL}" --numeric-version
  RESULT_VARIABLE cabal_result OUTPUT_VARIABLE cabal_version
  ERROR_VARIABLE cabal_error OUTPUT_STRIP_TRAILING_WHITESPACE TIMEOUT 10)
if(NOT cabal_result STREQUAL "0" OR
   NOT cabal_version MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" OR
   cabal_version VERSION_LESS "3.14.2.0")
  message(FATAL_ERROR
    "Unsupported cabal-install at '${ELEMENTS_CABAL}' (reported '${cabal_version}', result '${cabal_result}'). "
    "This fork requires cabal-install >= 3.14.2.0 with its GHC 9.6.7 toolchain; "
    "fresh Ubuntu 24.04 installs should use 3.16.1.0. Old distro Cabal can fail Hackage "
    "root-signature verification before building. See doc/build-unix.md#haskell-toolchain, "
    "then configure with -DELEMENTS_CABAL=/absolute/path/to/cabal. "
    "Keep secure repository verification enabled; do not reduce signature thresholds. ${cabal_error}")
endif()
message(STATUS "Using cabal-install ${cabal_version}: ${ELEMENTS_CABAL}")
