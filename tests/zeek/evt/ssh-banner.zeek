# @TEST-REQUIRES: have-zeek-plugin-jit
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ssh-single-conn.trace  ssh.spicy ./ssh.evt %INPUT >output
# @TEST-EXEC: btest-diff output
#
## @TEST-GROUP: spicy-core

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "SSH banner", c$id, is_orig, version, software;
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
    {
    print atype, aid;
    }

# @TEST-START-FILE ssh.spicy
module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    on %done { zeek::confirm_protocol(); }
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    port 22/tcp;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
