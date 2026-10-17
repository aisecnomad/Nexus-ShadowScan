"""How the timing guards that cite this module measure cost, and why.

The guards exist to catch algorithmic blow-up: a pattern that goes quadratic,
a sanitizer that rescans the same line per token. They used to measure *wall*
time, which answers a different question -- it includes every other process
competing for the core -- so under a parallel test run they failed on code
that was perfectly linear. One was reproducibly flaky under load and passed in
isolation.

They measure CPU time instead, each with its own inline bound::

    started = time.process_time()
    ...
    assert time.process_time() - started < 6

Algorithmic cost is CPU-bound, so this is both the stricter and the more
stable measurement: contention does not inflate it, while a genuine blow-up
still shows in full. No guard scales its bound by the machine's speed or
retries when it trips; each bound is fixed in the test.

CPU time cannot measure a cost that waits rather than computes, such as a
simulated slow filesystem, and a wall bound scaled by a load factor sampled
before or after the operation cannot see load that arrives during it.
``test_symbolic_link_checks_stop_at_the_listing_deadline`` therefore times
nothing: it gives the connector a clock that only the simulated link checks
advance, and counts how many checks the 3 s deadline lets through.

This module holds no helpers. A calibrated CPU budget with a retry and a
load-scaled wall budget lived here, and no guard used them.
"""
