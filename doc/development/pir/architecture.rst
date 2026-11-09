.. _pir_architecture:
.. _flattening_asts: https://www.cs.cornell.edu/~asampson/blog/flattening.html
.. _phi_upsilon: https://gist.github.com/pizlonator/79b0aa601912ff1a0eb1cb9253f5e98d

================
PIR Architecture
================

Parser Intermediate Representation (PIR) is a project which introduces a new intermediate
representation to Spicy. Currently, Spicy's :ref:`dev_architecture` can be simplified as
a compiler with two intermediate representations (IRs): a Spicy abstract syntax tree (AST)
and a HILTI AST. PIR is another IR which (currently) sits between the two.

For now, this is an experiment. PIR may end up as a core part of Spicy, but for now it is
staying as isolated as possible, in case the experiment turns out to not be fruitful.

Motivation
==========

PIR is made to solve a few real problems from Spicy.

#. Spicy is tightly coupled with C++.

   At the moment, the compilation path for Spicy very much assumes C++. The modules and
   linker are all connected with C++ as the assumed backend. The HILTI AST is essentially
   a minimized C++ AST with some extra high-level concepts. Then, there's no reasonably
   good way to "plug in" to get a different representation, such as Rust or a bytecode.

#. Parser behavior is encoded when lowering to HILTI.

   Currently, Spicy's codegen is done through a few "builders." These take Spicy code
   and lower to HILTI. There's nothing inherently problematic about this, but this step
   transforms the high-level parser behavior into C++-like code without much opportunity
   for optimization, or an alternative backend.

   This has caused a lot of hacky code in Spicy in order to optimize the lowered code.
   Since the behavior is encoded in the lowering step from Spicy to HILTI, it's
   surprisingly difficult to remove unneeded steps in parsing from Spicy. Then, HILTI
   has little to no understanding about the overall parser shape, just the procedural
   code. This results in feature constants, which are essentially just booleans, that
   are used to determine if we need certain blocks of code. Even removing unnecessary
   parser state that gets passed around has to be done by removing parameters and return
   values, rather than correcting a high-level understanding of what parser features are
   necessary.

#. There's no good way to make an alternative backend.

   We've had a number of requests for backends like Rust (or, simply questions). This is
   a very reasonable request, and exactly how many compilers do work! But, you have only
   bad options to do this as-is. You can add a backend to HILTI itself, which isn't too
   difficult. But, that only solves the end representation: you may be able to hack
   together a Rust backend, but it will still have many of the same issues as Spicy's C++
   code (or, worse).

   This may then force you into something even worse architecturally, like dumping Spicy's
   AST and using that by some lowerer. But, again, Spicy does not encode its actual parser
   behavior in the AST: there is a *ton* that is implicit within Spicy's AST. This route
   may look promising, but you're at the whim of changes to the Spicy AST and unit builder,
   which will inevitably cause drift or even implementations tied to an earlier Spicy
   version.

#. Spicy can be quite slow.

   We've had a pretty serious effort in the past to improve Spicy's parser speed, both in
   compilation and in runtime. When using Spicy's features, it can be slow, which is
   expected (Spicy is doing more work!). But, when *not* using those features, the
   optimizer does not have enough information to remove the scaffolding for many of the
   other issues, which may cause unnecessary burden in certain hot paths (like small
   subunits). Furthermore, Spicy generates so much code that both Spicy's optimizer and
   the C++ code generation have to work very hard in order to get reasonably performant code.

   Spicy is close to a reasonable limit for the time invested with the current
   architecture, but there is still a problem. Many parsers within Zeek still take
   minutes to compile. These parsers are often less performant than a native parser by
   a significant margin, so generally parsers don't get rewritten in Spicy. There's not
   too much more to do here without a rearchitecting.

So, what actually is PIR?

High Level Concepts
===================

Spicy's current architecture is to go through two IRs: Spicy, then HILTI. Then, the
compiler generates C++ code, and goes through that compilation process.

To start, PIR will hijack this: It will go Spicy, then PIR, then HILTI. This allows for
an easy integration path, since HILTI will still be able to generate code the same way
in order to integrate with Zeek and elsewhere. Eventually, the goal is for HILTI to be
an *optional* C++ backend. Other potential, future backends include Rust, C, or a custom
bytecode.

The PIR process itself only has a few major steps:

#. Build PIR from Spicy AST
#. Verify PIR
#. Optimize
#. Verify optimized PIR
#. Lower to HILTI

If any step surfaces an unsupported feature, PIR falls back to the "regular" lowerer to
HILTI (from Spicy AST).

PIR has two primary aims when lowering Spicy code. First, keep parser operations high
level, yet explicit. Second, make procedural code low-level, so it may benefit as much
as possible from optimizations.

For example, take this Spicy code:

.. spicy-code::

   module Test;

   type X = unit {
       x: uint8;
   };

   public type Message = unit {
       length: uint64;
       items: X[] &size=self.length;
   };

In PIR, parsing ``X`` is done through a variety of opcodes:

.. code::

   function %1 "" (parser.state) -> unit<@%0 "X"> [parser, unit=@%0 "X"]:
     region %1:
       block %13:
         %20 = core.argument 0 : parser.state
         %21 = unit.create @%0 "X" : unit<@%0 "X">
         %22 = parser.read_integer %20, width=8, signed=false, byte_order=network : tuple<parser.state, uint8>
         %23 = core.tuple_get %22, 0 : parser.state
         %24 = core.tuple_get %22, 1 : uint8
         %25 = parser.release_input %23 : parser.state
         %26 = unit.publish_field %21, %24, @%0 "X"::%0 "x" : unit<@%0 "X">
         %27: parser.finish %25, %26 : void

This is a function that gets called when parsing ``X``. It takes one argument, which is the
current state of the parser (this is how Spicy keeps track of where in the data stream we
are). Then it does what's needed to parse the field and finish parsing.

The vector has one special block in it in order to parse the vector of ``X``:

.. code::

   %46 = parser.repeat_to_bound %37, %38 : tuple<parser.state, vector<unit<@%0 "X">>>
           region %3:
             block %15:
               %39 = core.region_argument 0 : parser.state
               %40 = core.region_argument 1 : vector<unit<@%0 "X">>
               %41 = parser.parse_subunit %39, @function 1 : tuple<parser.state, unit<@%0 "X">>
               %42 = core.tuple_get %41, 0 : parser.state
               %43 = core.tuple_get %41, 1 : unit<@%0 "X">
               %44 = core.vector_append %40, %43 : vector<unit<@%0 "X">>
               %45: core.yield %42, %44 : void

This is a bit much to go into now, but the point is simple: All of this was encoded in
one line of Spicy code. In fact, much more is implicit, but many assumptions Spicy made
(such as when to pause for more input, or what to do on gaps in data) were baked directly
into the HILTI code. Now, they are explicit in each opcode, which may be used by
optimizations or analyses.

The parser code still leaves plenty of implementation details open. It's a high-level
shape to parse the given unit. But, procedural code looks much lower level. For example, take this Spicy function:

.. spicy-code::

   public function branchy(a: bool, b: bool, c: bool): int64 {
       if ( a ) {
           if ( b ) {
               return 1;
           }

           if ( c ) {
               return 3;
           }
       }
       else {
           if ( c ) {
               return 4;
           }
       }

       return 2;
   }

This would, in a high-level language, be modelled via ``If`` nodes, each with nested nodes
below it. Instead, this is all collapsed into a more assembly-like format:

.. code::

   function %0 "branchy" (bool, bool, bool) -> int64:
     region %0:
       block %0:
         %0 = core.argument 0 : bool
         %1 = core.argument 1 : bool
         %2 = core.argument 2 : bool
         %3: core.branch %0, then %1, else %2 : void
       block %1:
         %4: core.branch %1, then %3, else %4 : void
       block %2:
         %12: core.branch %2, then %9, else %10 : void
       block %3:
         %5 = core.int64_constant 1 : int64
         %6: core.return %5 : void
       block %4:
         %7: core.jump %5 : void
       block %5:
         %8: core.branch %2, then %6, else %7 : void
       block %6:
         %9 = core.int64_constant 3 : int64
         %10: core.return %9 : void
       block %7:
         %11: core.jump %8 : void
       block %8:
         %16: core.jump %12 : void
       block %9:
         %13 = core.int64_constant 4 : int64
         %14: core.return %13 : void
       block %10:
         %15: core.jump %11 : void
       block %11:
         %17: core.jump %12 : void
       block %12:
         %18 = core.int64_constant 2 : int64
         %19: core.return %18 : void

This makes the control flow through the program much simpler *to a computer*. That means
we can implement more optimizations, learn more about the program, and spend less time
walking through too many high-level concepts. It's all encoded in the IR, very explicitly.

All of this to say: PIR is designed to give a high-level understanding of parsing, but a
low-level understanding of procedural code. This lets PIR address Spicy's current
shortcomings in one, single IR.

Low Level Concepts
==================

PIR also has a few critical design decisions, but they're much more abstract. Here, we'll
go over a few of these and their motivation.

Flattened AST
-------------

Normally, an AST would contain direct pointers to its children. For example:

.. code:: cpp

   class If {
     Expression* condition;
     Block* then_block;
     Block* else_block;
   };

However, pointer indirection can be expensive. A compiler dereferences these many, many
times each time it compiles a program. This is how Spicy and HILTI currently work.

Instead, PIR took inspiration from Adrian Sampson's post `Flattening ASTs
<flattening_asts_>`_. This means that PIR passes around IDs, like ``TypeId``, ``FunctionId``,
``RegionId``, ``BlockId``, or ``InstId``. Each of these are stored in an ``Arena``.

For example, an ``Inst`` currently looks like:

.. code:: cpp

   struct Inst {
       Opcode opcode;
       TypeId result_type;
       std::vector<InstId> args;
       BlockId parent;
       InstPayload payload;
       std::vector<RegionId> regions; /**< regions owned by a structured operation */
       SourceSpanId span;
   };

You can see that an `Inst` does not contain a pointer to a type, but instead a `TypeId`.
This `TypeId` is little more than a `uint32_t`, which is itself an index into the arena.
The arena is basically just a vector of the underlying type.

For example, the instruction arena is defined like:

.. code:: cpp

       Arena<Inst, InstId> _instructions;

Which means that an `InstId` is an index into a vector, and the result is an `Inst` (which
we saw before).

Diagnostics
-----------

The diagnostics engine is revamped for PIR. The main motivation is so that more semantic
analyses can be added in the future, which could help with warnings (which are rare
in Spicy, mainly because they could be noisy and there's no suppression mechanism).
User diagnostics have stable IDs in a catalog. Suppress warnings with ``-W no-<id>``.
Errors cannot be suppressed. For example:

.. code:: cpp

   inline constexpr DiagnosticDefinition UnusedField{
       .id = "unused-field",
       .severity = DiagnosticSeverity::Warning,
       .message = "field '%s' is parsed but never used; consider making it 'skip'",
   };

An analysis reports the diagnostic at the affected field:

.. code:: cpp

   emitter.emit(diag::UnusedField, field, name);

Verifier failures are internal compiler errors. They cannot be suppressed and have no
catalog entries. Each check supplies a short tag so tests can identify it without
matching the message:

.. code:: cpp

   _emitter.emit("type-missing-declaration", "unit type does not reference a valid type declaration", id);

CFG and SSA
-----------

From the previous snippets, it's clear that the IR uses a control flow graph (CFG). This
is a standard CFG: a sequence of basic blocks. A basic block ends in a "terminator" which
may defer to one or more basic blocks. Once entering a basic block, each instruction
is executed sequentially, and no instruction can leave the block before reaching the
terminator (with few exceptions, such as parser suspension).

PIR also has a primitive form of single static assignment (SSA) form. Each instruction
result gets a separate result (the ``%XX`` numbers before the assignments in the PIR
snippets above). These are not reused. This helps with many dataflow analyses and analyses.

The goal will be to use a slightly different form of SSA, namely `Phi Upsilon form
<phi_upsilon_>`_. The purpose of that is to avoid complex tracking of SSA state while
creating nested branches, but it comes with a few more advantages outlined in that post.

This section will stay light on details, since it is not fully implemented.

Package Structure
-----------------

The central data structure for PIR is the ``Package``. Importantly, the package owns arenas,
meaning that any node lookup must go through the package.

Then, everything is broken down into a few core structures: Functions, which can be user
defined or parse functions. Functions own a root region, where regions are just
collections of blocks. Finally, the block is the sequence of instructions ending in a
terminator.

Note that regions are useful outside of functions, such as the ``RepeatToBound`` opcode.
