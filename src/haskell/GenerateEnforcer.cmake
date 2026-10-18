execute_process(COMMAND "${CABAL}" list-bin proto3-suite:exe:compile-proto-file
  "--project-file=${PROJECT}" "--builddir=${BUILD}"
  OUTPUT_VARIABLE compiler OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
foreach(schema cusf/common/v1/common.proto cusf/mainchain/v1/common.proto
    cusf/mainchain/v1/validator.proto cusf/mainchain/v1/wallet.proto)
  execute_process(COMMAND "${compiler}" --includeDir "${PROTO}" --includeDir "${GOOGLE}"
    --proto "${schema}" --out "${OUTPUT}" COMMAND_ERROR_IS_FATAL ANY)
endforeach()
