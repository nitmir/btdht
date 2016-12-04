btdht.krcp module
==================

.. automodule:: btdht.krcp
    :show-inheritance:

.. autoclass:: BError
    :show-inheritance:
    :undoc-members:
    :members:
    :exclude-members: e, t, y

    .. autoattribute:: e

        A list. The first element is an :class:`int` representing the error code.
        The second element is a string containing the error message

    .. autoattribute:: t

        string value representing a transaction ID, must be set to the query transaction ID
        for which an error is raises.

    .. autoattribute:: y

        The ``y`` key of the error message. For an error message, it is always ``b"e"``


.. autoclass:: GenericError
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: MethodUnknownError
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: ProtocolError
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: ServerError
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: BMessage
    :members:
    :undoc-members:
    :show-inheritance:
    :exclude-members: addr, errmsg, errno, q, t, v, y, decode, encode, get, response


    .. autoattribute:: addr

        The couple (ip, port) source of the message

    .. autoattribute:: errmsg

        The error message of the message if the message is and erro message

    .. autoattribute:: errno

        The error number of the message if the message is and erro message

    .. autoattribute:: q

        The ``q`` key of the message, should only be define if the message is a query (:attr:`y` is
        ``"q"``). It countains the name of the RPC method the query is asking for. Can be
        `b'ping'``, ``b'find_node'``, ``b'get_peers'``, ``b'announce_peer'``, ...

    .. autoattribute:: t

        The ``t`` key, a random string, transaction id used to match queries and responses together.

    .. autoattribute:: v

        The ``v`` key of the message. This attribute is not describe in the BEP5 that describe the
        bittorent DHT protocol. It it use as a version flag. Many bittorent client set it to
        the name and version of the client.

    .. autoattribute:: y

        The ``y` key of the message. Possible value are ``"q"`` for a query, `"r"` for a response
        and ``"e"`` for an error.


    .. automethod:: __getitem__(key)
    .. automethod:: __delitem__(key)
    .. automethod:: __setitem__(key, value)
    .. automethod:: decode(data, datalen)
    .. automethod:: encode
    .. automethod:: get(key, default=None)
    .. automethod:: response(dht)
