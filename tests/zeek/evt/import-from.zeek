# @TEST-REQUIRES: have-zeek-plugin
#
# @TEST-EXEC: mkdir -p a/b/c && mv y.spicy a/b/c
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ssh-single-conn.trace  ssh.spicy ./ssh.evt %INPUT >output
# @TEST-EXEC: btest-diff output
#
## @TEST-GROUP: spicy-core

event ssh::test(x: string, y: string)
	{
	print x, y;
	}

# @TEST-START-FILE ssh.spicy
module SSH;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    on %done {}
};
# @TEST-END-FILE

# @TEST-START-FILE x.spicy

module X;

public function x()  : string {
    return "Foo::x";
}

# @TEST-END-FILE

# @TEST-START-FILE y.spicy

module Y;

public function y()  : string {
    return "Foo::y";
}

# @TEST-END-FILE


# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    port 22/tcp;

import X;
import Y from a.b.c;

on SSH::Banner -> event ssh::test(X::x(), Y::y());
# @TEST-END-FILE
