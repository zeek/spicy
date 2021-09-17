.. _dev_benchmarking:

Benchmarking
============

End-to-end Parsers
------------------

We have a Benchmarking script that builds the HTTP and DNS parsers,
runs them on traces both with and without Zeek, and then reports total
execution times. The script also compares times against Zeek's
standard analyzers. The following summarizes how to use that script.

.. rubric:: Preparation

1. You need to build both Spicy and Zeek in release mode (which is the
   default for both).

2. You need sufficiently large traces of HTTP and DNS traffic and
   preprocess them into the right format. We normally use Zeek's `M57
   testsuite traces
   <https://github.com/zeek/zeek-testing/blob/master/traces.cfg>`_
   for this, and have prepared a prebuilt archive of the processed
   data that you can just download and extract:
   `spicy-benchmark-m57.tar.xz
   <https://download.zeek.org/data/spicy-benchmark-m57.tar.xz>`_
   (careful, it's large!).

   To preprocess some other trace ``trace.pcap``, do the following:

    - Extract HTTP and DNS sub-traces into ``spicy-http.pcap`` and
      ``spicy-dns.pcap``, respectively (do not change the file names)::

        # tcpdump -r trace.pcap -w spicy-http.pcap tcp port 80
        # tcpdump -r trace.pcap -w spicy-dns.pcap udp port 53

    - Run Zeek on these traces with the ``record-spicy-batch.zeek`` script that
      comes with Spicy::

        # zeek -br spicy-http.pcap zeek/scripts/record-spicy-batch.zeek SpicyBatch::filename=spicy-http.dat
        # zeek -br spicy-dns.pcap  zeek/scripts/record-spicy-batch.zeek SpicyBatch::filename=spicy-dns.dat

    - Move traces and resulting data files into a separate directory::

        # mkdir my-benchmark-data
        # mv spicy-{http,dns}.pcap spicy-{http,dns}.data my-benchmark-data/

    - Now you can use that ``my-benchmark-data/`` directory with the
      Benchmarking script, as shown below.

.. rubric:: Execution

1. Use ``scripts/run-benchmark`` script to build/recompile the
   parsers. It's easiest to run out of the Spicy build directory (see
   its usage message for setting paths otherwise). Watch for warnings
   about accidentally using debug versions of Spicy or Zeek::

    # cd build
    # ../scripts/run-benchmark build

   This will put all precompiled code into ``./benchmark``.

2. Run the benchmark script with a directory containing your preprocessed data.
   If you're using the provided M57 archive::

    # ../scripts/run-benchmark -t /path/to/spicy-benchmark-m57/long run

        http-static  1.58        1.54        1.56
          http-hlto  1.74        1.75        1.75
    http-zeek-spicy  4.97        4.87        5.02          conn.log=2752  http.log=4833
      http-zeek-std  3.69        3.59        3.74          conn.log=2752  http.log=4906

         dns-static  0.01        0.01        0.01
           dns-hlto  0.01        0.01        0.01
     dns-zeek-spicy  0.97        0.94        0.97          conn.log=3458   dns.log=3458
       dns-zeek-std  0.80        0.76        0.76          conn.log=3464   dns.log=3829

   Each line is three executions of the same command. Values are user time in seconds.

.. rubric: Profiling

The ``run-benchmark`` script leaves its precompiled code in a
subdirectory ``./benchmark``. In particular, you will find static
binaries there that you can profile. For example, with ``perf`` on
Linux::

    # perf record  --call-graph dwarf -g ./benchmark/http-opt -U -F spicy-benchmark-m57/long/spicy-http.dat
    # perf report -G

Microbenchmarks
---------------

.. todo:: Add fiber benchmark.
