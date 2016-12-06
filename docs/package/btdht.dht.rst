btdht.dht module
================

.. automodule:: btdht.dht
    :members:
    :undoc-members:
    :show-inheritance:
    :exclude-members: DHT_BASE, DHT, Node, Bucket, RoutingTable


.. autosummary::

    DHT
    DHT_BASE
    Node
    Bucket
    RoutingTable

.. autoclass:: DHT
    :show-inheritance:
    :members:
    :undoc-members:


.. autoclass:: DHT_BASE
    :show-inheritance:
    :members:
    :undoc-members:
    :exclude-members: bind_ip, bind_port, debuglvl, last_msg, last_msg_rep, ignored_ip, ignored_net,
        myid, prefix, prefix, prefix, stoped, threads, token, mytoken, transaction_type, to_send,
        to_schedule, zombie, root, sock,
        save, load, start, stop, stop_bg, init_socket, is_alive, debug, sleep, bootstarp,
        build_table, announce_peer, get_peers, get_closest_nodes, sendto, clean, clean_long,
        register_message, on_announce_peer_response, on_announce_peer_query, on_find_node_query,
        on_find_node_response, on_get_peers_query, on_get_peers_response, on_ping_query,
        on_ping_response, on_error

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

    .. autoattribute:: zombie


    .. automethod:: save(filename=None, max_node=None)
    .. automethod:: load(filename=None, max_node=None)
    .. automethod:: start(start_routing_table=True, start_scheduler=True)
    .. automethod:: stop
    .. automethod:: stop_bg
    .. automethod:: init_socket
    .. automethod:: is_alive

    .. automethod:: debug(lvl, msg)
    .. automethod:: sleep(t, fstop=None)

    .. automethod:: bootstarp(
        addresses=[
            ("router.utorrent.com", 6881),
            ("grenade.genua.fr", 6880),
            ("dht.transmissionbt.com", 6881)
        ]
    )
    .. automethod:: build_table
    .. automethod:: announce_peer(info_hash, port, delay=0, block=True)
    .. automethod:: get_peers(hash, delay=0, block=True, callback=None, limit=10)

    .. automethod:: get_closest_nodes(id, compact=False)
    .. automethod:: sendto(msg, addr)

    .. automethod:: clean
    .. automethod:: clean_long

    .. automethod:: register_message(msg)

    .. automethod:: on_announce_peer_response(query, response)
    .. automethod:: on_announce_peer_query(query)
    .. automethod:: on_find_node_query(query)
    .. automethod:: on_find_node_response(query, response)
    .. automethod:: on_get_peers_query(query)
    .. automethod:: on_get_peers_response(query, response)
    .. automethod:: on_ping_query(query)
    .. automethod:: on_ping_response(query, response)
    .. automethod:: on_error(error, query=None)


.. autoclass:: Node
    :show-inheritance:
    :members:
    :undoc-members:
    :exclude-members: port, last_response, last_query, failed, id, good, bad, ip,
        compact_info, from_compact_infos, from_compact_info, announce_peer, find_node, get_peers,
        ping

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

    .. automethod:: compact_info
    .. automethod:: from_compact_infos(infos)
    .. automethod:: from_compact_info(info)
    .. automethod:: announce_peer(dht, info_hash, port)
    .. automethod:: find_node(dht, target)
    .. automethod:: get_peers(dht, info_hash)
    .. automethod:: ping(dht)

.. autoclass:: Bucket
    :show-inheritance:
    :members:
    :undoc-members:
    :exclude-members: max_size, last_changed, id, id_length, own, random_id, get_node, add, split,
        merge, to_refresh

    .. autoattribute:: max_size

        Maximun number of element in the bucket

    .. autoattribute:: last_changed

        Unix timestamp, last time the bucket had been updated

    .. autoattribute:: id

        A prefix identifier from 0 to 160 bits for the bucket

    .. autoattribute:: id_length

        Number of signifiant bit in :attr:`id`

    .. autoattribute:: to_refresh

    .. automethod:: random_id
    .. automethod:: add(dht, node)
    .. automethod:: get_node(id)
    .. automethod:: own(id)
    .. automethod:: split(rt, dht)
    .. automethod:: merge(bucket)

.. autoclass:: RoutingTable
    :show-inheritance:
    :members:
    :undoc-members:
    :exclude-members: debuglvl, trie, stoped, need_merge, threads, to_schedule, prefix, zombie,
        stop_bg, stop, start, is_alive, register_torrent, release_torrent, register_torrent_longterm,
        release_torrent_longterm, register_dht, release_dht, empty, debug, stats, heigth, get_node,
        find, get_closest_nodes, add, split, merge

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

    .. autoattribute:: zombie


    .. automethod:: start
    .. automethod:: stop
    .. automethod:: stop_bg
    .. automethod:: is_alive

    .. automethod:: register_torrent(id)
    .. automethod:: release_torrent(id)
    .. automethod:: register_torrent_longterm(id)
    .. automethod:: release_torrent_longterm(id)
    .. automethod:: register_dht(dht)
    .. automethod:: release_dht(dht)
    .. automethod:: empty

    .. automethod:: debug(lvl, msg)
    .. automethod:: stats()
    .. automethod:: heigth

    .. automethod:: find(id)
    .. automethod:: get_node(id)
    .. automethod:: get_closest_nodes(id, bad=False)
    .. automethod:: add(dht, node)
    .. automethod:: split(dht, bucket)
    .. automethod:: merge
