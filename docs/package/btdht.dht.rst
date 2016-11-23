btdht.dht module
================

.. automodule:: btdht.dht
    :show-inheritance:

.. autoclass:: BucketFull
    :show-inheritance:
    :members:
    :undoc-members:
.. autoclass:: BucketNotFull
    :show-inheritance:
    :members:
    :undoc-members:
.. autoclass:: NoTokenError
    :show-inheritance:
    :members:
    :undoc-members:
.. autoclass:: NotFound
    :show-inheritance:
    :members:
    :undoc-members:
.. autoclass:: FailToStop
    :show-inheritance:
    :members:
    :undoc-members:


.. autoclass:: DHT_BASE
    :show-inheritance:
    :members:

    .. autoattribute:: ignored_net

        :class:`list` of default ignored ip networks

    .. autoattribute:: root

        :class:`RoutingTable` the used instance of the routing table 

    .. autoattribute:: bind_port

        :class:`int` port the dht is binded to

    .. autoattribute:: bind_ip

        :class:`str` interface the dht is binded to

    .. autoattribute:: myid

        :class:`utils.ID` the dht instance id, 160bits long (20 Bytes)

    .. autoattribute:: debuglvl

        :class:`int` the dht instance verbosity level

    .. autoattribute:: threads

        :class:`list` of the :class:`Thread<threading.Thread>` of the dht instance

    .. autoattribute:: transaction_type

        Map beetween transaction id and messages type (to be able to match responses)

    .. autoattribute:: token

        Token send with get_peers response. Map between ip addresses and a list of random token.
        A new token by ip is genereted at most every 5 min, a single token is valid 10 min.
        On reception of a announce_peer query from ip, the query is only accepted if we have a
        valid token (generated less than 10min ago).

    .. autoattribute:: mytoken

        Tokens received on get_peers response. Map between ip addresses and received token from ip.
        Needed to send announce_peer to that particular ip.

    .. autoattribute:: sock

        The current dht :class:`socket.Socket`

    .. autoattribute:: stoped

        the state (stoped ?) of the dht


.. autoclass:: DHT
    :show-inheritance:
    :undoc-members:

.. autoclass:: Node
    :show-inheritance:
    :members:
    :undoc-members:

.. autoclass:: Bucket
    :show-inheritance:
    :members:
    :undoc-members:

.. autoclass:: SplitQueue
    :show-inheritance:
    :members:
    :undoc-members:

.. autoclass:: RoutingTable
    :show-inheritance:
    :members:
    :undoc-members:

