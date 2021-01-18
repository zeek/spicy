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
    %mime-type = "text/plain";
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE text.evt

file analyzer spicy::Text:
    parse with Text::Data;

on Text::Data -> event text::data($file, self.data);
# @TEST-END-FILE
