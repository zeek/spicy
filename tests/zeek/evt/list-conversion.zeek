# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ssh-single-conn.trace listconv.spicy ./listconv.evt %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE listconv.spicy

module listconv;

public function bro_convert(a: uint8) : tuple<uint64, uint64> {
    return (a, a + 1);
}

public type Test = unit {
    a: list<uint8> &count=5;
    b: int16;
    c: uint16;
};

@TEST-END-FILE

@TEST-START-FILE listconv.evt

protocol analyzer listconv over TCP:
    parse originator with listconv::Test,
    port 22/tcp;

on listconv::Test -> event listconv::test($conn,
                                  $is_orig,
                                  [listconv::bro_convert(i) for i in self.a],
                                  self.b,
                                  self.c
                                  );

@TEST-END-FILE

type int_tuple: record {
  a: count;
  b: count;
};

event listconv::test(x: connection,
                 is_orig: bool,
                 a: vector of int_tuple,
                 b: int,
                 c: count
                ) {
  print x$id;
  print is_orig;
  print a;
  print b;
  print c;
}
