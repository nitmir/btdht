btdht: A python implementation of the Bittorrent distributed hash table
=======================================================================

|github_version| |pypi_version| |licence| |doc|

The aim of btdht is to provide a powerful implementation of the Bittorrent
mainline DHT easily extended to build application over the DHT.
The author currently uses it to crawl the dht and has been able to retrieve
more than 200.000 torrents files a day.

The implementation is fully compliant with the `BEP5 <http://www.bittorrent.org/beps/bep_0005.html>`_
and the kademlia paper [#]_ (with a predominance of the BEP5 over the paper)
For example, this implementation uses a bucket-based approach for the routing table.


.. contents:: Table of Contents

Dependencies
------------

* python 2.7 or 3.4 or above
* `datrie <https://pypi.python.org/pypi/datrie>`_
* `netaddr <https://pypi.python.org/pypi/netaddr>`_


Build dependencies
------------------

* A C compiler
* `cython <https://pypi.python.org/pypi/Cython>`_
* python header files


Installation
------------

The recommended installation mode is to use a `virtualenv <https://virtualenv.pypa.io/en/stable/>`__.

To Install ``btdht`` using the last published release, run::

    $ pip install btdht

Alternatively if you want to use the version of the git repository, you can clone it::

    $ git clone https://github.com/nitmir/btdht
    $ cd btdht
    $ pip install -r requirements-dev.txt

Then, run ``make install`` to compile the sources and create a python package and install it with pip.

For installing or building on linux and unix systems, you will need a C compiler and the python
headers (installing the packages ``build-essential`` and ``python-dev`` should be enough on debian
like systems, you'll probably gonna need ``make``, ``gcc``, ``python2-devel`` and ``redhat-rpm-config``
on centos like systems).

On windows systems, we provide pre-builded releases for python 2.7 and 3.5 so just running
``pip install btdht`` should be fine. If you want to build from the sources of the repository or,
for another python version, you will also need a `C compiler <https://wiki.python.org/moin/WindowsCompilers>`__.


Usage examples
--------------

Search for the peers announcing the torrent ``0403fb4728bd788fbcb67e87d6feb241ef38c75a``
(`Ubuntu 16.10 Desktop (64-bit) <http://releases.ubuntu.com/16.10/ubuntu-16.10-desktop-amd64.iso.torrent>`__)

.. code-block:: python

    >>> import btdht
    >>> import binascii
    >>> dht = btdht.DHT()
    >>> dht.start()  # now wait at least 15s for the dht to boostrap
    init socket for 4c323257aa6c4c5c6ccae118db93ccce5bb05d92
    Bootstraping
    >>> dht.get_peers(binascii.a2b_hex("0403fb4728bd788fbcb67e87d6feb241ef38c75a"))
    [
        ('81.171.107.75', 17744),
        ('94.242.250.86', 3813),
        ('88.175.164.228', 32428),
        ('82.224.107.213', 61667),
        ('85.56.118.178', 6881),
        ('78.196.28.4', 38379),
        ('82.251.140.70', 32529),
        ('78.198.108.3', 10088),
        ('78.235.153.136', 10619),
        ('88.189.113.32', 33192),
        ('81.57.9.183', 5514),
        ('82.251.17.155', 14721),
        ('88.168.207.178', 31466),
        ('82.238.89.236', 32970),
        ('78.226.209.88', 2881),
        ('5.164.219.48', 6881),
        ('78.225.252.39', 31002)
    ]

Subsequent calls to get_peers may return more peers.

You may also inherit ``btdht.DHT_BASE`` and overload some of the ``on_`msg`_(query|response)``
functions. See the `doc <http://btdht.readthedocs.io>`_ for a full overview of the ``btdht`` API.


.. [#] Maymounkov, P., & Mazieres, D. (2002, March). Kademlia: A peer-to-peer information system
       based on the xor metric. In International Workshop on Peer-to-Peer Systems (pp. 53-65).
       Springer Berlin Heidelberg.


.. |pypi_version| image:: https://badges.genua.fr/pypi/v/btdht.svg
    :target: https://pypi.python.org/pypi/btdht

.. |github_version| image:: https://badges.genua.fr/github/tag/nitmir/btdht.svg?label=github
    :target: https://github.com/nitmir/btdht/releases/latest

.. |licence| image:: https://badges.genua.fr/pypi/l/btdht.svg
    :target: https://www.gnu.org/licenses/gpl-3.0.html

.. |doc| image:: https://badges.genua.fr/local/readthedocs/?version=latest
    :target: http://btdht.readthedocs.io
