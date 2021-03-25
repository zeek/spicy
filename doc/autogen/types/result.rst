.. rubric:: Methods

.. spicy:method:: result::error result error False error ()

    Retrieves the error stored inside the result instance. Will throw a
    ``NoError`` exception if the result is not in an error state.

.. rubric:: Operators

.. spicy:operator:: result::Deref <dereferenced~type> op:* t:result op:

    Retrieves value stored inside the result instance. Will throw a
    ``NoResult`` exception if the result is in an error state.

