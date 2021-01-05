# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ssh-single-conn.trace tupleenum.spicy ./tupleenum.evt %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init() {
  local i: TupleEnum::TestEnum;

  i = TupleEnum::TestEnum_A;

  print i;
}

# @TEST-START-FILE tupleenum.evt

# @TEST-END-FILE

# @TEST-START-FILE tupleenum.spicy

module TupleEnum;

public type TestEnum = enum {
    A = 83, B = 84, C = 85
};

# @TEST-END-FILE
