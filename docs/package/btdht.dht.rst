btdht.dht module
================

.. automodule:: btdht.dht
    :show-inheritance:


.. autoclass:: DHT_BASE
    :show-inheritance:
    :members:

    .. autoattribute:: bind_ip

        :class:`str` interface the dht is binded to

    .. autoattribute:: bind_port

        :class:`int` port the dht is binded to

    .. autoattribute:: debuglvl

        :class:`int` the dht instance verbosity level

    .. autoattribute:: last_msg

        last time we received any message

    .. autoattribute:: last_msg_rep

        last time we receive a response to one of our messages

    .. autoattribute:: ignored_ip

        :class:`set` of ignored ip in dotted notation

    .. autoattribute:: ignored_net

        :class:`list` of default ignored ip networks

    .. autoattribute:: myid

        :class:`utils.ID` the dht instance id, 160bits long (20 Bytes)

    .. autoattribute:: prefix

       :class:`str` prefixing all debug message

    .. autoattribute:: root

        :class:`RoutingTable` the used instance of the routing table

    .. autoattribute:: sock

        The current dht :class:`socket.socket`

    .. autoattribute:: stoped

        the state (stoped ?) of the dht

    .. autoattribute:: threads

        :class:`list` of the :class:`Thread<threading.Thread>` of the dht instance

    .. autoattribute:: token

        Token send with get_peers response. Map between ip addresses and a list of random token.
        A new token by ip is genereted at most every 5 min, a single token is valid 10 min.
        On reception of a announce_peer query from ip, the query is only accepted if we have a
        valid token (generated less than 10min ago).

    .. autoattribute:: mytoken

        Tokens received on get_peers response. Map between ip addresses and received token from ip.
        Needed to send announce_peer to that particular ip.

    .. autoattribute:: transaction_type

        Map beetween transaction id and messages type (to be able to match responses)

    .. autoattribute:: to_send

        A :class:`PollableQueue` of messages (data, (ip, port)) to send

    .. autoattribute:: to_schedule

        A list of looping iterator to schedule, passed to :attr:`_scheduler`


.. autoclass:: DHT
    :show-inheritance:
    :members:
    :undoc-members:

.. autoclass:: Node
    :show-inheritance:
    :members:

    .. autoattribute:: port

        UDP port of the node

    .. autoattribute:: last_response

        Unix timestamp of the last received response from this node

    .. autoattribute:: last_query

        Unix timestamp of the last received query from this node

    .. autoattribute:: failed

        Number of reponse pending (increase on sending query to the node, set to 0 on reception from
        the node)

    .. autoattribute:: id

        160bits (20 Bytes) identifier of the node

    .. autoattribute:: good

        ``True`` if the node is a good node. A good node is a node has responded to one of our
        queries within the last 15 minutes. A node is also good if it has ever responded to one of
        our queries and has sent us a query within the last 15 minutes.

    .. autoattribute:: bad

        ``True`` if the node is a bad node (communication with the node is not possible). Nodes
        become bad when they fail to respond to 3 queries in a row.

    .. autoattribute:: ip

        IP address of the node in dotted notation


.. autoclass:: Bucket
    :show-inheritance:
    :members:

    .. autoattribute:: max_size

        Maximun number of element in the bucket

    .. autoattribute:: last_changed

        Unix timestamp, last time the bucket had been updated

    .. autoattribute:: id

        A prefix identifier from 0 to 160 bits for the bucket

    .. autoattribute:: id_length

        Number of signifiant bit in :attr:`id`

.. autoclass:: RoutingTable
    :show-inheritance:
    :members:

    .. autoattribute:: debuglvl

        :class:`int` the routing table instance verbosity level

    .. autoattribute:: trie

        The routing table storage data structure, an instance of :class:`datrie.Trie`

    .. autoattribute:: stoped

        The state (stoped ?) of the routing table

    .. autoattribute:: need_merge

        Is a merge sheduled ?

    .. autoattribute:: threads

        :class:`list` of the :class:`Thread<threading.Thread>` of the routing table instance

    .. autoattribute:: to_schedule

        A class:`list` of couple (weightless thread name, weightless thread function)

    .. autoattribute:: prefix

        Prefix in logs and threads name

