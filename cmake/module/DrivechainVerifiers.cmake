# The verifier archives are consensus dependencies, not optional substitutes.
# Builds without them retain the runtime fail-closed activation checks.
include(CheckCXXSourceCompiles)
include(CMakePushCheckState)

set(USDD_SP1_VERIFIER_ARCHIVE "" CACHE FILEPATH "Pinned USDD SP1 verifier static archive")
set(ECX_SP1_VERIFIER_ARCHIVE "" CACHE FILEPATH "ECX SP1 6.3.1 Groth16 and custody verifier static archive")
set(USDD_SP1_VERIFIER_NATIVE_LIBS "" CACHE STRING "USDD Rust archive native link libraries")
set(ECX_SP1_VERIFIER_SYSTEM_LIBS "" CACHE STRING "ECX Rust archive native link libraries")
set(ECX_FORCED_V3_ADMISSION_ARCHIVE "" CACHE FILEPATH "Candidate canonical ECXFv3 signature adapter archive (does not activate swaps)")
set(ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS "" CACHE STRING "Exact forced admission Rust archive native libraries")
foreach(kind USDD_SP1_VERIFIER ECX_SP1_VERIFIER ECX_FORCED_V3_ADMISSION)
  set(${kind}_SHA256 "" CACHE STRING "Independently trusted SHA256 of ${kind}_ARCHIVE")
endforeach()
add_library(drivechain_verifiers INTERFACE)

function(check_drivechain_archive archive_variable pin_variable)
  set(archive "${${archive_variable}}")
  if(NOT IS_ABSOLUTE "${archive}" OR NOT EXISTS "${archive}" OR IS_DIRECTORY "${archive}" OR "${archive}" MATCHES "[ \t\r\n]")
    message(FATAL_ERROR "Verifier archive must be an existing absolute file path without whitespace: ${archive}")
  endif()
  if(APPLE)
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
      message(FATAL_ERROR "Set CMAKE_OSX_DEPLOYMENT_TARGET explicitly for verifier builds.")
    endif()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(
      COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/contrib/devtools/check_macos_deployment_target.py"
        --target "${CMAKE_OSX_DEPLOYMENT_TARGET}" "${archive}"
      RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
      message(FATAL_ERROR "Verifier archive has a missing or mismatched macOS deployment target: ${archive}")
    endif()
  endif()
  set(ARCHIVE "${archive}")
  set(EXPECTED_SHA256 "${${pin_variable}}")
  include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CheckPinnedArchive.cmake")
  # Link a verified build-local snapshot, never the mutable external input.
  set(snapshot "${PROJECT_BINARY_DIR}/pinned-verifiers/${EXPECTED_SHA256}.a")
  if(IS_SYMLINK "${snapshot}")
    message(FATAL_ERROR "Refusing symlink verifier snapshot: ${snapshot}")
  endif()
  if(EXISTS "${snapshot}")
    set(ARCHIVE "${snapshot}")
    include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CheckPinnedArchive.cmake")
  endif()
  configure_file("${archive}" "${snapshot}" COPYONLY)
  set(ARCHIVE "${snapshot}")
  include("${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CheckPinnedArchive.cmake")
  add_custom_target(check_${archive_variable}
    COMMAND "${CMAKE_COMMAND}" "-DARCHIVE=${archive}" "-DEXPECTED_SHA256=${EXPECTED_SHA256}"
      -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CheckPinnedArchive.cmake"
    COMMAND "${CMAKE_COMMAND}" "-DARCHIVE=${snapshot}" "-DEXPECTED_SHA256=${EXPECTED_SHA256}"
      -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CheckPinnedArchive.cmake"
    VERBATIM
  )
  add_dependencies(drivechain_verifiers check_${archive_variable})
  # `cmake --install` need not run the build dependencies. Gate that entry point
  # too, before elementsconsensus installs its private verifier archives.
  install(CODE "
    set(ARCHIVE [==[${snapshot}]==])
    set(EXPECTED_SHA256 [==[${EXPECTED_SHA256}]==])
    include([==[${CMAKE_CURRENT_FUNCTION_LIST_DIR}/CheckPinnedArchive.cmake]==])
  " ALL_COMPONENTS)
  set(${archive_variable} "${snapshot}" PARENT_SCOPE)
endfunction()

if(USDD_SP1_VERIFIER_ARCHIVE)
  check_drivechain_archive(USDD_SP1_VERIFIER_ARCHIVE USDD_SP1_VERIFIER_SHA256)
  if(NOT USDD_SP1_VERIFIER_NATIVE_LIBS)
    if(APPLE)
      set(USDD_SP1_VERIFIER_NATIVE_LIBS "-framework Security;-framework CoreFoundation;iconv")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(USDD_SP1_VERIFIER_NATIVE_LIBS "dl;pthread;m")
    else()
      message(FATAL_ERROR "Set USDD_SP1_VERIFIER_NATIVE_LIBS for ${CMAKE_SYSTEM_NAME}.")
    endif()
  endif()
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES "${USDD_SP1_VERIFIER_ARCHIVE}" ${USDD_SP1_VERIFIER_NATIVE_LIBS})
  unset(USDD_SP1_ABI_LINKS CACHE)
  check_cxx_source_compiles([[
    #include <cstddef>
    #include <cstdint>
    extern "C" {
    uint32_t usdd_sp1_verifier_abi_version(void);
    uint32_t usdd_sp1_verifier_semantic_identity_version(void);
    uint32_t usdd_sp1_verifier_semantic_identity(uint8_t*, size_t);
    uint32_t usdd_sp1_verify_annex(uint32_t, const uint8_t*, size_t,
      const uint8_t*, size_t, const uint8_t*, size_t);
    }
    int main() {
      uint8_t identity[32]{};
      return usdd_sp1_verifier_abi_version() + usdd_sp1_verifier_semantic_identity_version()
        + usdd_sp1_verifier_semantic_identity(identity, sizeof(identity))
        + usdd_sp1_verify_annex(0, nullptr, 0, nullptr, 0, nullptr, 0);
    }
  ]] USDD_SP1_ABI_LINKS)
  cmake_pop_check_state()
  if(NOT USDD_SP1_ABI_LINKS)
    message(FATAL_ERROR "The pinned USDD verifier ABI does not link. Check the archive and native libraries.")
  endif()
  set(HAVE_USDD_SP1_VERIFIER 1)
  target_compile_definitions(drivechain_verifiers INTERFACE HAVE_USDD_SP1_VERIFIER=1)
  target_link_libraries(drivechain_verifiers INTERFACE "${USDD_SP1_VERIFIER_ARCHIVE}" ${USDD_SP1_VERIFIER_NATIVE_LIBS})
endif()

if(ECX_FORCED_V3_ADMISSION_ARCHIVE)
  check_drivechain_archive(ECX_FORCED_V3_ADMISSION_ARCHIVE ECX_FORCED_V3_ADMISSION_SHA256)
  if(NOT ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS)
    if(APPLE)
      set(ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS "iconv;System;c;m")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS "dl;pthread;m")
    else()
      message(FATAL_ERROR "Set ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS for ${CMAKE_SYSTEM_NAME}.")
    endif()
  endif()
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES "${ECX_FORCED_V3_ADMISSION_ARCHIVE}" ${ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS})
  unset(ECX_FORCED_V3_ABI_LINKS CACHE)
  check_cxx_source_compiles([[
    #include <cstddef>
    #include <cstdint>
    extern "C" uint32_t ecx_forced_v3_abi_version();
    extern "C" int32_t ecx_forced_v3_verify_payload(const uint8_t*,size_t,const uint8_t*,const uint8_t*,size_t,uint8_t*,size_t);
    int main() { return ecx_forced_v3_abi_version()+ecx_forced_v3_verify_payload(nullptr,0,nullptr,nullptr,0,nullptr,0); }
  ]] ECX_FORCED_V3_ABI_LINKS)
  cmake_pop_check_state()
  if(NOT ECX_FORCED_V3_ABI_LINKS)
    message(FATAL_ERROR "The exact forced admission ABI does not link.")
  endif()
  target_compile_definitions(drivechain_verifiers INTERFACE HAVE_ECX_FORCED_V3_ADMISSION=1)
  target_link_libraries(drivechain_verifiers INTERFACE "${ECX_FORCED_V3_ADMISSION_ARCHIVE}" ${ECX_FORCED_V3_ADMISSION_SYSTEM_LIBS})
endif()

if(ECX_SP1_VERIFIER_ARCHIVE)
  check_drivechain_archive(ECX_SP1_VERIFIER_ARCHIVE ECX_SP1_VERIFIER_SHA256)
  if(NOT ECX_SP1_VERIFIER_SYSTEM_LIBS)
    if(APPLE)
      set(ECX_SP1_VERIFIER_SYSTEM_LIBS "iconv;System;c;m")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(ECX_SP1_VERIFIER_SYSTEM_LIBS "dl;pthread;m")
    else()
      message(FATAL_ERROR "Set ECX_SP1_VERIFIER_SYSTEM_LIBS for ${CMAKE_SYSTEM_NAME}.")
    endif()
  endif()
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES "${ECX_SP1_VERIFIER_ARCHIVE}" ${ECX_SP1_VERIFIER_SYSTEM_LIBS})
  unset(ECX_SP1_ABI_LINKS CACHE)
  check_cxx_source_compiles([[
    #include <cstddef>
    #include <cstdint>
    extern "C" {
    bool ecx_sp1_6_3_1_verify_groth16_sha256(void*, const uint8_t*, size_t, const uint32_t*, const uint8_t*);
    bool ecx_witness_availability_verify_custody_receipts_v1(
      const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
    }
    int main() {
      const bool proof = ecx_sp1_6_3_1_verify_groth16_sha256(nullptr, nullptr, 0, nullptr, nullptr);
      const bool custody = ecx_witness_availability_verify_custody_receipts_v1(nullptr, 0, nullptr, 0, nullptr, 0);
      return proof || custody;
    }
  ]] ECX_SP1_ABI_LINKS)
  cmake_pop_check_state()
  if(NOT ECX_SP1_ABI_LINKS)
    message(FATAL_ERROR "ECX requires both the SP1 6.3.1 Groth16 and custody ABIs; another archive is not a substitute.")
  endif()
  set(ECX_ENABLE_SP1_GROTH16_VERIFIER 1)
  target_compile_definitions(drivechain_verifiers INTERFACE ECX_ENABLE_SP1_GROTH16_VERIFIER=1)
  target_link_libraries(drivechain_verifiers INTERFACE "${ECX_SP1_VERIFIER_ARCHIVE}" ${ECX_SP1_VERIFIER_SYSTEM_LIBS})
endif()
