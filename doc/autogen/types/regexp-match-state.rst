.. rubric:: Methods

.. spicy:method:: regexp_match_state::advance spicy::MatchState advance False tuple<int<32>,~view<stream>> (data: bytes, final: bool = True)

    Feeds a chunk of data into the token match state, continuing matching
    where it left off last time. If *final* is true, this is assumed to be
    the final piece of data; any further advancing will then lead to an
    exception. Returns a 2-tuple with (1) an integer match indicator with
    the same semantics as that returned by ``regexp::match()``; and (2)
    the number of bytes in *data* consumed by the matching. The state must
    not be used again once an integer larger or equal zero has been
    returned.

.. spicy:method:: regexp_match_state::advance spicy::MatchState advance False tuple<int<32>,~view<stream>> (data: view<stream>)

    Feeds a chunk of data into the token match state, continuing matching
    where it left off last time. If the underlying view is frozen, this
    will be assumed to be last piece of data; any further advancing will
    then lead to an exception. Returns a 2-tuple with (1) an integer match
    indicator with the same semantics as that returned by
    ``regexp::match()``; and (2) a new view that's trimming *data* to the
    part not yet consumed. The state must not be used again once an
    integer larger or equal zero has been returned.

