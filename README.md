btdht: An event based implementation of the Bittorrent distributed hashtable
============================================================================


The aim of btdht is to provide a powerfull implementation of the Bittorrent
mailine DHT easily subclassed to build application over the DHT.
The author currently use it to crawl the dht and has been able to retrive
more than 200.000 torrents files by days.

The implementation is fully compliant with the [BEP5](http://www.bittorrent.org/beps/bep_0005.html)
and the kademlia paper (with a predominance of the BEP5 overt the paper)
For example this implementation use a bucket-based approach for the routing table.

## Requirements
 * cython
 * [datrie](https://github.com/kmike/datrie)
