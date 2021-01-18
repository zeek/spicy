# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/http-post.trace text.spicy ./text.evt %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff output
#
## @TEST-GROUP: spicy-core

event text::data(f: fa_file, data: string)
	{
	print "text data", f$id, data;
	}

# @TEST-START-FILE text.spicy
module Text;

public type Data = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE text.evt

file analyzer spicy::Text:
    parse with Text::Data,

    # Note that Zeek determines the MIME type not from the Content-Type
    # header in the trace, but by content sniffing (i.e., libmagic-style)
    mime-type text/plain;
    #mime-type application/x-www-form-urlencoded;

on Text::Data -> event text::data($file, self.data);
# @TEST-END-FILE
