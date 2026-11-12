# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

# The debug stream goes to stderr, so check both streams.
execute_process(
    COMMAND
        "${SPICYC}" --experimental-pir --strict-public-api -W no-unused-field -p -D spicy-pir
        "${SOURCE}"
    RESULT_VARIABLE status
    OUTPUT_VARIABLE output
    ERROR_VARIABLE diagnostics
)

set(_all "${output}\n${diagnostics}")

if(
    NOT status EQUAL 0
    OR NOT _all MATCHES "attached PIR-produced HILTI module"
    OR _all MATCHES "falling back"
    OR _all MATCHES "HILTI backend unsupported"
)
    message(FATAL_ERROR "${SOURCE} did not compile through the PIR route: ${diagnostics}")
endif()
