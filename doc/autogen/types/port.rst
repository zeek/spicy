.. rubric:: Methods

.. spicy:method:: port::protocol port protocol False hilti::Protocol ()

    Returns the protocol the port is using (such as UDP or TCP).

.. rubric:: Operators

.. spicy:operator:: port::Call port port(uint<16>, enum)

    Creates a port instance.

.. spicy:operator:: port::Equal bool t:port <sp> op:== <sp> t:port

    Compares two port values.

.. spicy:operator:: port::Unequal bool t:port <sp> op:!= <sp> t:port

    Compares two port values.

