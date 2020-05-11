.. rubric:: Methods

.. spicy:method:: regexp::find regexp find False int<32> (data: bytes)

    Searches the regular expression in *data*. If found, returns an
    integer that's greater than zero. If multiple patterns have been
    compiled for parallel matching, that integer will be the ID of the
    matching pattern. Returns -1 if the regular expression is not found,
    but could still match if more data were added to the input. Returns 0
    if the regular expression is not found and adding more data wouldn't
    change anything.

.. spicy:method:: regexp::find_groups regexp find_groups False vector<bytes> (data: bytes)

    Searches the regular expression in *data*. If the regular expression
    is found, returns a vector with one entry for each capture group
    defined by the regular expression; starting at index 1. Each of these
    entries is a view locating the matching bytes. In addition, index 0
    always contains the data that matches the full regular expression.
    Returns an empty vector if the expression is not found. This method is
    not compatible with pattern sets and will throw a runtime exception if
    used with a regular expression compiled from a set.

.. spicy:method:: regexp::find_span regexp find_span False tuple<int<32>,~bytes> (data: bytes)

    Searches the regular expression in *data*. Returns a 2-tuple with (1)
    a integer match indicator with the same semantics as that returned by
    ``find``; and (2) if a match has been found, the data that matches the
    regular expression.

.. spicy:method:: regexp::token_matcher regexp token_matcher False ::hilti::rt::regexp::MatchState ()

    Initializes state for matching regular expression incrementally
    against chunks of future input. The regular expression will be
    considered implicitly anchored. The regular expression must have been
    compiled with the ``&nosub`` attribute.

