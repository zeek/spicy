# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

execute_process(
    COMMAND "${SPICYC}" --experimental-pir --strict-public-api -p -D spicy-pir "${SOURCE}"
    RESULT_VARIABLE status
    OUTPUT_VARIABLE output
    ERROR_VARIABLE diagnostics)

if (NOT status EQUAL 0
    OR NOT output MATCHES "module __spicy_pir_backend"
    OR NOT output MATCHES "parse_root_0"
    OR NOT output MATCHES "parse_child_0"
    OR diagnostics MATCHES "falling back")
    message(
        FATAL_ERROR
            "bounded-vector benchmark did not select the PIR-generated root and child: ${diagnostics}"
    )
endif ()
