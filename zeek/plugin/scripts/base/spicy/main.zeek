
# doc-start
module Spicy;

export {
    # Activate compile-time debugging output for given debug streams (comma-separated list).
    const codegen_debug = "" &redef;

    # Enable debug mode for code generation.
    const debug = F &redef;

    # If debug is true, add selected additional instrumentation (comma-separated list).
    const debug_addl = "" &redef;

    # Save all generated code into files on disk.
    const dump_code = F &redef;

    # Enable optimization for code generation.
    const optimize = F &redef;

    # Report a break-down of compiler's execution time.
    const report_times = F &redef;

    # Disable code valdidation.
    const skip_validation = F &redef;
}
# doc-end

event spicy_analyzer_for_mime_type(a: Files::Tag, mt: string)
    {
    Files::register_for_mime_type(a, mt);
    }
