# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ssh-single-conn.trace dtest.spicy ./dtest.evt %INPUT | sort >output
# @TEST-EXEC: btest-diff output

event dtest_one(x: dtest::RESULT) {
    print "one", x;
}

event dtest_two(x: dtest::RESULT) {
    print "two", x;
}

# @TEST-START-FILE dtest.evt

protocol analyzer spicy::dtest over TCP:
    parse originator with dtest::Message,
    port 22/tcp;

on dtest::Message if ( self.sswitch == 83 )
  -> event dtest_one(self.result);

on dtest::Message if ( self.sswitch != 83 )
  -> event dtest_two(self.result);

# @TEST-END-FILE
# @TEST-START-FILE dtest.spicy

module dtest;

public type RESULT = enum {
 A, B = 83, C, D, E, F
};

public type Message = unit {
  sswitch: uint8;
  result: uint8 &convert=RESULT($$);
};

# @TEST-END-FILE
