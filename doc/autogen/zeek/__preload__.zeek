
# doc-common-start
module Spicy;

export {
# doc-options-start
    # Constant for testing if Spicy is available.
    const available = T;

    ## Show output of Spicy print statements.
    const enable_print = F &redef;

    ## abort() instead of throwing HILTI exceptions.
    const abort_on_exceptions = F &redef;

    ## Include backtraces when reporting unhandled exceptions.
    const show_backtraces = F &redef;

    ## Maximum depth of recursive file analysis (Spicy analyzers only)
    const max_file_depth: count = 5 &redef;
# doc-options-end
}
