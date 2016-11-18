btdht: An event based implementation of the Bittorrent distributed hash table
=============================================================================


The aim of btdht is to provide a powerful implementation of the Bittorrent
mainline DHT easily extended to build application over the DHT.
The author currently uses it to crawl the dht and has been able to retrieve
more than 200.000 torrents files a day.

The implementation is fully compliant with the `BEP5 <http://www.bittorrent.org/beps/bep_0005.html>`_
and the kademlia paper [#]_ (with a predominance of the BEP5 over the paper)
For example, this implementation uses a bucket-based approach for the routing table.

Requirements
------------
 * `cython <https://pypi.python.org/pypi/Cython>`_
 * `datrie <https://pypi.python.org/pypi/datrie>`_
 * `netaddr <https://pypi.python.org/pypi/netaddr>`_




.. [#] Maymounkov, P., & Mazieres, D. (2002, March). Kademlia: A peer-to-peer information system
       based on the xor metric. In International Workshop on Peer-to-Peer Systems (pp. 53-65).
       Springer Berlin Heidelberg.
