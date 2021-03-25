.. rubric:: Methods

.. spicy:method:: network::family net family False hilti::AddressFamily ()

    Returns the protocol family of the network, which can be IPv4 or IPv6.

.. spicy:method:: network::length net length False int<64> ()

    Returns the length of the network's prefix.

.. spicy:method:: network::prefix net prefix False addr ()

    Returns the network's prefix as a masked IP address.

.. rubric:: Operators

.. spicy:operator:: network::Equal bool t:net <sp> op:== <sp> t:net

    Compares two network values.

.. spicy:operator:: network::In bool t:addr <sp> op:in <sp> t:net

    Returns true if the address is part of the network range.

.. spicy:operator:: network::InInv bool t:addr <sp> op:!in <sp> t:net

    Performs the inverse of the corresponding ``in`` operation.

.. spicy:operator:: network::Unequal bool t:net <sp> op:!= <sp> t:net

    Compares two network values.

