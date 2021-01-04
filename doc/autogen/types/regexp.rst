.. rubric:: Methods

.. spicy:method:: regexp::find regexp find False tuple<int<32>,~bytes> (data: bytes)

    Searches the regular expression in *data* and returns the matching
    part. Different from ``match``, this does not anchor the expression to
    the beginning of the data: it will find matches at arbitrary starting
    positions. Returns a 2-tuple with (1) an integer match indicator with
    the same semantics as that returned by ``find``; and (2) if a match
    has been found, the data that matches the regular expression. (Note:
    Currently this function has a runtime that's quadratic in the size of
    *data*; consider using `match` if performance is an issue.)

.. spicy:method:: regexp::match regexp match False int<32> (data: bytes)

    Matches the regular expression against *data*. If it matches, returns
    an integer that's greater than zero. If multiple patterns have been
    compiled for parallel matching, that integer will be the ID of the
    matching pattern. Returns -1 if the regular expression does not match
    the data, but could still yield a match if more data were added.
    Returns 0 if the regular expression is not found and adding more data
    wouldn't change anything. The expression is considered anchored, as
    though it starts with an implicit ``^`` regexp operator, to the
    beginning of the data.

.. spicy:method:: regexp::match_groups regexp match_groups False vector<bytes> (data: bytes)

    Matches the regular expression against *data*. If it matches, returns
    a vector with one entry for each capture group defined by the regular
    expression; starting at index 1. Each of these entries is a view
    locating the matching bytes. In addition, index 0 always contains the
    data that matches the full regular expression. Returns an empty vector
    if the expression is not found. The expression is considered anchored,
    as though it starts with an implicit ``^`` regexp operator, to the
    beginning of the data. This method is not compatible with pattern sets
    and will throw a runtime exception if used with a regular expression
    compiled from a set.

.. spicy:method:: regexp::token_matcher regexp token_matcher False hilti::MatchState ()

    Initializes state for matching regular expression incrementally
    against chunks of future input. The expression is considered anchored,
    as though it starts with an implicit ``^`` regexp operator, to the
    beginning of the data.

