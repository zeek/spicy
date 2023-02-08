.. rubric:: Methods

.. spicy:method:: barrier::abort barrier() abort False void ()

    Aborts the barrier, causing any waiting parties to throw a
    ``BarrierAborted`` exception. This has no effect if the barrier is
    already released or aborted.

.. spicy:method:: barrier::arrive barrier() arrive False void ()

    Signals a party's arrival at the barrier, potentially releasing it if
    the expected number of parties have been seen now. This has no effect
    if the barrier is already released or aborted.

.. spicy:method:: barrier::arrive_and_wait barrier() arrive_and_wait False void ()

    Convenience method combining a `arrive()` with an immediately
    following `wait()`.

.. spicy:method:: barrier::wait barrier() wait False void ()

    Blocks the caller until the barrier is released by the expected number
    of parties arriving. If the barrier is already released, it will
    return immediately. If the barrier gets aborted before or during the
    wait, the method will throw a ``BarrierAborted`` exception.

.. rubric:: Operators

.. spicy:operator:: barrier::Call barrier() barrier(uint)

    Creates a barrier that will wait for the given number of parties.

