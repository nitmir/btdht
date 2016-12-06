btdht.utils module
==================

.. automodule:: btdht.utils
    :members:
    :undoc-members:
    :show-inheritance:
    :exclude-members: ID, PollableQueue, Scheduler, id_to_longid, nbit, nflip, nset, enumerate_ids,
        bencode, bdecode, ip_in_nets

.. autosummary::
    bencode
    bdecode
    enumerate_ids
    id_to_longid
    ip_in_nets
    nbit
    nflip
    nset
    ID
    PollableQueue
    Scheduler

.. autofunction:: bencode(obj)
.. autofunction:: bdecode(s)
.. autofunction:: enumerate_ids(size, id)
.. autofunction:: id_to_longid(id, l=20)
.. autofunction:: ip_in_nets(ip, nets)
.. autofunction:: nbit(s, n)
.. autofunction:: nflip(s, n)
.. autofunction:: nset(s, n , i)

.. autoclass:: ID
    :show-inheritance:
    :members:
    :undoc-members:
    :exclude-members: value, to_bytes, startswith

    .. autoattribute:: value

        :class:`bytes`, Actual value of the :class:`ID`

    .. automethod:: to_bytes(id)
    .. automethod:: startswith(s)
    .. automethod:: __getitem__(i)
    .. automethod:: __xor__(other)

.. autoclass:: PollableQueue
    :show-inheritance:
    :members:
    :undoc-members:
    :inherited-members:
    :exclude-members: sock

    .. autoattribute:: sock

        A :class:`socket.socket` object ready for read then here is something to pull from the queue



.. autoclass:: Scheduler
    :show-inheritance:
    :members:
    :undoc-members:
    :exclude-members: zombie, start, stop, stop_bg, is_alive, thread_alive, add_dht, del_dht,
        add_thread, del_thread

    .. autoattribute:: zombie

    .. automethod:: start(name_prefix="scheduler")
    .. automethod:: stop
    .. automethod:: stop_bg
    .. automethod:: is_alive
    .. automethod:: thread_alive(name)
    .. automethod:: add_dht(dht)
    .. automethod:: del_dht(dht)
    .. automethod:: add_thread(name, function, user=False)
    .. automethod:: del_thread(name, stop_if_empty=True)
