# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: ${ZEEK} -Cr ${TRACES}/udp.trace udp-test.spicy ./udp-test.evt %INPUT >output
# @TEST-EXEC: btest-diff output

event udp_test::message(c: connection, is_orig: bool, data: string)
	{
	print "UDP packet", c$id, is_orig, data;
	}

# @TEST-START-FILE udp-test.spicy
module UDPTest;

public type Message = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE udp-test.evt
protocol analyzer spicy::UDP_TEST over UDP:
    parse with UDPTest::Message,
    port 31337/udp;

on UDPTest::Message -> event udp_test::message($conn, $is_orig, self.data);
# @TEST-END-FILE
