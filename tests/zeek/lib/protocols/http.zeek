# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: spicyz -o http.hlto ${DIST}/spicy/lib/protocols/http.spicy ${DIST}/zeek/plugin/lib/protocols/http.evt
# @TEST-EXEC: ${SCRIPTS}/run-zeek -NN http.hlto | grep -q spicy_HTTP
# @TEST-EXEC: ${SCRIPTS}/run-zeek -r ${TRACES}/http-post.trace frameworks/files/hash-all-files http.hlto %INPUT | sort >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff http.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff files.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff output

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    print c$id;

    for ( i in hlist )
	    print hlist[i]$name, hlist[i]$value;
    }
