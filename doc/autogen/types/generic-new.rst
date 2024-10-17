.. spicy:operator:: generic::New T& new <sp> t:T

    Returns a :ref:`reference <type_reference>` to an instance of a type
    newly allocated on the heap. If ``T`` is a type, a default instance of
    that type will be allocated. If the type expects any parameters, they
    must be provided through a corresponding argument tuple: ``new
    T(ARG_1,...ARG_N)``. If ``T`` is a constant, an instance of its type
    will be allocated and initialized with the value. Other types of
    expressions are not allowed.

