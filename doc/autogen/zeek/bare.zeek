@load base/frameworks/notice
@load base/misc/version

# doc-common-start
module Spicy;

export {
# doc-functions-start
    ## Enable a specific Spicy protocol analyzer if not already active. If this
    ## analyzer replaces an standard analyzer, that one will automatically be
    ## disabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global enable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;

    ## Disable a specific Spicy protocol analyzer if not already inactive. If
    ## this analyzer replaces an standard analyzer, that one will automatically
    ## be re-enabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global disable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;


    # The following functions are only available with Zeek versions > 4.0.

@if ( Version::number >= 40100 )
    ## Enable a specific Spicy file analyzer if not already active. If this
    ## analyzer replaces an standard analyzer, that one will automatically be
    ## disabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global enable_file_analyzer: function(tag: Files::Tag) : bool;

    ## Disable a specific Spicy file analyzer if not already inactive. If
    ## this analyzer replaces an standard analyzer, that one will automatically
    ## be re-enabled.
    ##
    ## tag: analyzer to toggle
    ##
    ## Returns: true if the operation succeeded
    global disable_file_analyzer: function(tag: Files::Tag) : bool;
@endif
# doc-functions-end

    redef enum Notice::Type += { Spicy_Max_File_Depth_Exceeded };
}

event spicy_analyzer_for_mime_type(a: Files::Tag, mt: string)
    {
    Files::register_for_mime_type(a, mt);
    }

function enable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }

@if ( Version::number >= 40100 )
function enable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }
@endif

event max_file_depth_exceeded(f: fa_file, args: Files::AnalyzerArgs, limit: count)
    {
    NOTICE([
            $note=Spicy::Spicy_Max_File_Depth_Exceeded,
            $msg=fmt("Maximum file depth exceeded for file %s", f$id)
    ]);
    }
