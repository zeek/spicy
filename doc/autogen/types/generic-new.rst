.. spicy:operator:: generic::New T& new <sp> t:T

    Returns a :ref:`reference <type_reference>` to an instance of a type
    newly allocated on the heap. If ``T`` is a type, a default instance of
    that type will be allocated. If ``T`` is an expression, an instance of
    the expression's type will be allocated and initialized with the value
    of the expression.

