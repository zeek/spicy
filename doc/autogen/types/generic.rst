.. rubric:: Operators

.. spicy:operator:: generic::Begin <iterator> begin(<container>)

    Returns an iterator to the beginning of the container's content.

.. spicy:operator:: generic::End <iterator> end(<container>)

    Returns an iterator to the end of the container's content.

.. spicy:operator:: generic::New strong_ref<T> new <sp> t:<any>

    Returns a reference to an instance of a type newly allocated on the
    heap. If `x' is a type, a default instance of that type will be
    allocated. If `x` is an expression, an instance of the expression's
    type will be allocated and initialized with the value of the
    expression.

.. spicy:operator:: generic::Pack <packable> pack <sp> t:tuple

    Packs a value into a binary representation.

.. spicy:operator:: generic::Unpack <unpackable> unpack <sp> t:any-type

    Unpacks a value from a binary representation.

