# -*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015 Valentin Samir

from libc.string cimport strlen, strncmp, strcmp, strncpy, strcpy
from libc.stdlib cimport atoi, malloc, free

import os
import IN
import sys
import time
import six
import heapq
import traceback
import struct
import socket
import select
import collections
import netaddr
import binascii
try:
    import Queue
except ImportError:
    import queue as Queue
from functools import total_ordering, reduce
from threading import Thread, Lock
from random import shuffle, randint

import datrie

import utils
from utils import ID, nbit, nflip, nset, SplitQueue, PollableQueue

from .krcp cimport BMessage
from .krcp import BError, ProtocolError, GenericError, ServerError, MethodUnknownError, MissingT
from .krcp import DecodeError


cdef class DHT_BASE:
    """
    The DHT base class

    :param RoutingTable routing_table: An optional routing table, possibly shared between several
        dht instances. If not specified, a new routing table is instanciated.
    :param int bind_port: And optional udp port to use for the dht instance. If not specified, the
        hosting system will choose an available port.
    :param str bind_ip: The interface to listen to. The default is ``"0.0.0.0"``.
    :param bytes id: An optional 160 bits long (20 Bytes) id. If not specified, a random one is
        generated.
    :param set ignored_ip: A set of ip address in dotted (``"1.2.3.4"``) notation to ignore.
        The default is the empty set.
    :param int debuglvl: Level of verbosity, default to ``0``.
    :param str prefix: A prefix to use in logged messages. The default is ``""``.
    :param int process_queue_size: Size of the queue of messages waiting to be processed by user
        defines functions (on_`msg`_(query|response)). see the :meth:`register_message` method.
        The default to ``500``.
    :param list ignored_net: An list of ip networks in cidr notation (``"1.2.3.4/5"``) to ignore.
        The default is the value of the attribute :attr:`ignored_net`.

    Note:
        try to use same ``id`` and ``bind_port`` over dht restart to increase
        the probability to remain in other nodes routing table

    """
    cdef char _myid[20]

    #: :class:`list` of default ignored ip networks
    ignored_net = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32'
    ]
    #: :class:`str` prefixing all debug message
    prefix = ""
    #: :class:`set` of ignored ip in dotted notation
    ignored_ip = []
    #: :class:`RoutingTable` the used instance of the routing table 
    root = None
    #: :class:`int` port the dht is binded to
    bind_port = None
    #: :class:`str` interface the dht is binded to
    bind_ip = "0.0.0.0"
    #: :class:`utils.ID` the dht instance id, 160bits long (20 Bytes)
    myid = None
    #: :class:`int` the dht instance verbosity level
    debuglvl = 0
    #: :class:`list` of the :class:`Thread<threading.Thread>` of the dht instance
    threads = []
    #: Map beetween transaction id and messages type (to be able to match responses)
    transaction_type = {}
    #: Token send with get_peers response. Map between ip addresses and a list of random token.
    #: A new token by ip is genereted at most every 5 min, a single token is valid 10 min.
    #: On reception of a announce_peer query from ip, the query is only accepted if we have a
    #: valid token (generated less than 10min ago).
    token = collections.defaultdict(list)
    #: Tokens received on get_peers response. Map between ip addresses and received token from ip.
    #: Needed to send announce_peer to that particular ip.
    mytoken = {}
    #: The current dht :class:`socket.Socket`
    sock = None
    #: A :class:`PollableQueue` of messages (data, (ip, port)) to send
    to_send = PollableQueue()
    #: the state (stoped ?) of the dht
    stoped = True
    #: last time we received any message
    last_msg = 0
    #: last time we receive a response to one of our messages
    last_msg_rep = 0
    #: A list of looping iterator to schedule. Calling :meth:`schedule` will do a scheduling for
    #: 1 DHT instance
    to_schedule = []



    #: Map torrent hash -> peer ip and port -> received time. hash, ip and port are from
    #: announce_peer query messages. time is the time of the received message. We only keep the
    #: 100 most recent (ip, port). A (ip, port) couple is kept max 30min 
    _peers=collections.defaultdict(collections.OrderedDict)
    #: Map torrent hash -> peer ip and port -> received time. hash, ip and port are from get_peers
    #: response messages. time is the time of the received message. We keep the 1000 most recent
    #: (ip, port). A (ip, port) couple is kept max 15min 
    _got_peers=collections.defaultdict(collections.OrderedDict)
    #: internal heap structure used to find the K closed nodes in the DHT from one id
    _get_peer_loop_list = []
    #: Map hash -> time. Pseudo lock structure to ensure we only run background process for
    #: :meth:`get_peers` only once by hash
    _get_peer_loop_lock = {}
    #: same as previous but for :meth:`announce_peer`
    _get_closest_loop_lock = {}
    #: A queue of DHT messages to send to user defined function (on_`msg`_(query|response)).
    #: See the :meth:`register_message` method.
    _to_process = None
    #: A set of messages name (e.g. ``b"find_node"``, ``b"ping"``, ``b"get_peers"``,
    #: ``b"announce_peer"``) for which we call user defined functions.
    #: See the :meth:`register_message` method.
    _to_process_registered = set()
    #: internal list of supposed alive threads
    _threads = []
    #: internal list of supposed zombie (asked to stop but still running) threads
    _threads_zombie = []
    #: last debug message, use to prevent duplicate messages over 5 seconds
    _last_debug = ""
    #: time of the lat debug message, use to prevent duplicate messages over 5 seconds
    _last_debug_time = 0
    #: number of received messages since the last time :meth:`socket_stats` was called
    _socket_in = 0
    #: number of sended messages since the last time :meth:`socket_stats` was called
    _socket_out = 0
    #: last time :meth:`socket_stats` was called
    _last_socket_stats = 0
    #: last time the long background cleaning was run
    _long_clean = 0
    #: heigth of the routing table (a binary tree) during the last run of :meth:`_routine`
    _root_heigth = 0
    #: a :class:`utils.Scheduler` instance
    _scheduler = None


    def __init__(self, routing_table=None, bind_port=None, bind_ip="0.0.0.0",
      id=None, ignored_ip=[], debuglvl=0, prefix="", process_queue_size=500,
      ignored_net=None, scheduler=None
    ):
        if self.__class__ == DHT_BASE:
            raise RuntimeError(
                "DHT_BASE cannot be directly instantiated, use DHT instead or any subclass that"
                " may have be defined"
            )
        # checking the provided id or picking a random one
        if id is not None:
            if len(id) != 20:
                raise ValueError("id must be 20 char long")
            id = ID.to_bytes(id)
        else:
            id = ID().value
        self.myid = ID(id)

        # initialize the scheduler
        self._scheduler = utils.Scheduler() if scheduler is None else scheduler

        # initialising the routing table
        self.root = RoutingTable(scheduler=self._scheduler, prefix=prefix) if routing_table is None else routing_table

        self.bind_port = bind_port
        self.bind_ip = bind_ip

        self.ignored_ip = ignored_ip
        if ignored_net is not None:
            self.ignored_net = [netaddr.IPNetwork(net) for net in ignored_net]
        else:
            self.ignored_net = [netaddr.IPNetwork(net) for net in self.ignored_net]
        self.debuglvl = debuglvl
        self.prefix = prefix

        # initialize public attributes
        self.threads = []
        self.transaction_type = {}
        self.token = collections.defaultdict(list)
        self.mytoken = {}
        self.stoped = True
        self.last_msg = 0
        self.last_msg_rep = 0

        # initialize private attributes
        self._peers=collections.defaultdict(collections.OrderedDict)
        self._got_peers=collections.defaultdict(collections.OrderedDict)
        self._get_peer_loop_list = []
        self._get_peer_loop_lock = {}
        self._get_closest_loop_lock = {}
        self._to_process_registered = set()
        self._threads = []
        self._threads_zombie = []
        self._last_debug = ""
        self._last_debug_time = 0
        self._socket_in = 0
        self._socket_out = 0
        self._last_socket_stats = 0
        self._long_clean = 0
        self._root_heigth = 0
        self._to_process = PollableQueue(maxsize=process_queue_size)

        self.to_schedule = [
            ("%sroutine" % self.prefix, self._routine, False),
            ("%sget_peers_closest_loop" % self.prefix, self._get_peers_closest_loop, False),
            ("%sprocess_loop" % self.prefix, self._process_loop, True)
        ]

    def save(self, filename=None, max_node=None):
        """save the current list of nodes to ``filename``.

        :param str filename: An optional filename where to save the current list of nodes.
            If not provided, the file ``"dht_`myid`.status`` is used.
        :param int max_node: An optional integer to limit the number of saved nodes.
            If not provided, all of the routing table nodes are saved.
        """
        nodes_nb = 0
        if filename is None:
            myid = binascii.b2a_hex(self.myid.value)
            filename = "dht_%s.status" % myid
        with open(filename, 'wb') as f:
            for bucket in self.root.trie.values():
                for node in bucket:
                    if node.good:
                        f.write(node.compact_info())
                        if max_node is not None:
                            nodes_nb+=1
                            if nodes_nb >= max_node:
                                return

    def load(self, filename=None, max_node=None):
        """load a list of nodes from ``filename``.

        :param str filename: An optional filename where to load the list of nodes.
            If not provided, the file ``"dht_`myid`.status`` is used.
        :param int max_node: An optional integer to limit the number of loaded nodes.
            If not provided, all of the file nodes are loaded.
        """
        nodes_nb = 0
        if filename is None:
            myid = binascii.b2a_hex(self.myid.value)
            filename = "dht_%s.status" % myid
        try:
            with open(filename, 'rb') as f:
                nodes = f.read(26*100)
                while nodes:
                    for node in Node.from_compact_infos(nodes):
                        self.root.add(self, node)
                        if max_node is not None:
                            nodes_nb+=1
                            if nodes_nb >= max_node:
                                return
                    nodes = f.read(26*100)
        except IOError as e:
            self.debug(0, str(e))

    def stop_bg(self):
        """Lauch the stop process of the dht and return immediately"""
        if not self.stoped:
            t=Thread(target=self.stop)
            t.daemon = True
            t.start()

    def stop(self):
        """
            Stop the dht:

              * Set the attribute :attr:`stoped` to ``True`` and wait for threads to terminate
              * Close the dht socket

            :raises FailToStop: if there is still some alive threads after 30 secondes, with the
                list of still alive threads as parameter.
        """
        if self.stoped:
            self.debug(0, "Already stoped or stoping in progress")
            return
        self._scheduler.del_dht(self)
        self.root.release_dht(self)
        self.stoped = True
        self._threads = [t for t in self._threads[:] if t.is_alive()]
        #self.debug(0, "Trying to terminate thread for 1 minutes")
        for i in range(0, 30):
            if self._threads:
                if i > 5:
                    self.debug(0, "Waiting for %s threads to terminate" % len(self._threads))
                time.sleep(1)
                self._threads = [t for t in self._threads[:] if t.is_alive()]
            else:
                break
        if self._threads:
            self.debug(
                0,
                "Unable to stop %s threads, giving up:\n%r" % (len(self._threads), self._threads)
            )
            self._threads_zombie.extend(self._threads)
            self._threads = []

        if self.sock:
            try:self.sock.close()
            except: pass

        if self._threads_zombie:
            raise FailToStop(self._threads_zombie)

    @property
    def zombie(self):
        """``True`` if dht is stopped but one thread or more remains alive, ``False`` otherwise"""
        return bool(self.stoped and [t for t in self._threads if t.is_alive()])

    def start(self, start_routing_table=True, start_scheduler=True):
        """
            Start the dht:
                * initialize some attributes
                * register this instance of the dht in the routing table
                  (see :meth:`RoutingTable.register_dht`)
                * initialize the dht socket (see :meth:init_socket)
                * start the routing table if needed and ``start_routing_table` is ``True``
                * start the scheduler if needed and ``start_scheduler`` is ``True``

            :param bool start_routing_table: If ``True`` (the default) also start the routing table
                if needed
            :param bool start_scheduler: If ``True``(the default) alsp start the scheduler
        """
        if not self.stoped:
            self.debug(0, "Already started")
            return
        if self.zombie:
            self.debug(0, "Zombie threads, unable de start")
            return self._threads_zombie

        self.stoped = False
        self._root_heigth = 0
        self._socket_in = 0
        self._socket_out = 0
        self._last_socket_stats = time.time()
        self.last_msg = time.time()
        self.last_msg_rep = time.time()
        self._long_clean = time.time()

        self.init_socket()

        self.root.register_dht(self)
        self._scheduler.add_dht(self)

        if start_routing_table and self.root.stoped:
            self.root.start()
        if start_scheduler and self._scheduler._stoped:
            self._scheduler.start()

    def is_alive(self):
        """Test if all threads of the dht are alive, stop the dht if one of the thread is dead

        :return: ``True`` if all dht threads are alive, ``False`` otherwise and stop all remaining
            threads.
        :rtype: bool
        """
        weigthless_threads_satus = [
            self._scheduler.thread_alive(s[0]) for s in self.to_schedule
        ]
        if (
            self.threads is not None and
            all([t.is_alive() for t in self.threads])
            and all(weigthless_threads_satus)
        ):
            return True
        elif not self._threads and self.stoped and not any(weigthless_threads_satus):
            return False
        else:
            self.debug(0, "One thread died, stopping dht")
            self.stop_bg()
            return False

    def debug(self, lvl, msg):
        """
        Print ``msg`` prefixed with :attr:`prefix` if ``lvl`` <= :attr:`debuglvl`

        :param int lvl: The debug level of the message to print
        :param str msg: The debug message to print

        Note:
            duplicate messages are removed:
        """
        if (
            lvl <= self.debuglvl and 
            (self._last_debug != msg or (time.time() - self._last_debug_time) > 5)
        ):
            print(self.prefix + msg)
            self._last_debug = msg
            self._last_debug_time = time.time()

    def _socket_stats(self):
        """
        Display some statistic on send/received messages

        :return: A tuple (number of received messages, number of sended messages, periode of time)
        :rtype: tuple

        Note:
            The counter are reset to 0 on each call
        """
        now = time.time()
        in_s = self._socket_in
        self._socket_in = 0
        out_s = self._socket_out
        self._socket_out = 0
        delta = now - self._last_socket_stats
        self._last_socket_stats = now
        return (in_s, out_s, delta)

    def init_socket(self):
        """Initialize the UDP socket of the DHT"""
        self.debug(0, "init socket for %s" % binascii.b2a_hex(self.myid.value))
        if self.sock:
             try:self.sock.close()
             except: pass
        # initialize the sending queue
        self.to_send = PollableQueue()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, IN.IP_MTU_DISCOVER, IN.IP_PMTUDISC_DO)
        self.sock.setblocking(0)
        if self.bind_port:
            try:
                self.sock.bind((self.bind_ip, self.bind_port))
            except socket.error:
                self.debug(-10, "fail to bind to port %s" % self.bind_port)
                raise
        else:
            self.sock.bind((self.bind_ip, 0))
            # set :attr:`bind_port` to the port choosen by the system
            self.bind_port = self.sock.getsockname()[1]

    def sleep(self, t, fstop=None):
        """
            Sleep for t seconds. If the dht is requested to be stop, run ``fstop()`` and exit

            :param float t: A time to sleep, in seconds
            :param fstop: A callable with no arguments, called before exiting

            Note:
                Dont use it in the main thread otherwise it can exit before child threads.
                Only use it in child threads

        """
        if t>0:
            t_int = int(t)
            t_dec = t - t_int
            for i in range(0, t_int):
                time.sleep(1)
                if self.stoped:
                    if fstop:
                        fstop()
                    sys.exit(0)
            time.sleep(t_dec)


    def announce_peer(self, info_hash, port, delay=0, block=True):
        """
            Announce that the ``info_hash`` is available on ``port`` to the K closest nodes from
            ``info_hash`` found in the whole dht.

            :param bytes info_hash: A 160 bits (20 Bytes) long identifier to announce
            :param int port: The tcp port of with ``info_hash`` if available
            :param int delay: An optional delay in second to wait before starting to look for the K
                closest nodes into the dht. The default is ``0``.
            :param bool block: If ``True`` (the default) wait until the announce in done to the K
                closest nodes. Otherwise, return immediately.
        """
        def callback(nodes):
            for node in nodes:
                try:
                    node.announce_peer(self, info_hash, port)
                except NoTokenError:
                    node.get_peers(self, info_hash)
                    self.debug(1, "No token to announce on node %s" % node)
        if block:
            while info_hash in self._get_closest_loop_lock and not self.stoped:
                self.sleep(0.1)
        if not info_hash in self._get_closest_loop_lock:
            self._get_closest_loop_lock[info_hash]=time.time()
            self.debug(2, "get closest hash %s" % binascii.b2a_hex(info_hash))
            self.root.register_torrent(info_hash)
            tried_nodes = set()
            ts = time.time() + delay
            closest = self.get_closest_nodes(info_hash)
            typ = "closest"
            heapq.heappush(
                self._get_peer_loop_list,
                (ts, info_hash, tried_nodes, closest, typ, callback, None)
            )
            if block:
                while info_hash in self._get_closest_loop_lock and not self.stoped:
                    self.sleep(0.1)

    def _add_peer(self, info_hash, ip, port):
        """
            Store a peer after a announce_peer query

            :param bytes info_hash: A 160 bits (20 Bytes) long identifier the peer is offering
            :param str ip: The ip address of the peer in dotted notation (``"1.2.3.4"``)
            :param int port: The tcp port of the peer

            Note:
                The peer address is store 30 minutes
        """
        if ip not in self.ignored_ip and not utils.ip_in_nets(ip, self.ignored_net):
            self._peers[info_hash][(ip,port)]=time.time()
            # we only keep at most 100 peers per hash
            if len(self._peers[info_hash]) > 100:
                self._peers[info_hash].popitem(False)

    def _add_peer_queried(self, info_hash, ip, port):
        """
            Store a peer after a get_peer response

            :param bytes info_hash: A 160 bits (20 Bytes) long identifier the peer is offering
            :param str ip: The ip address of the peer in dotted notation (``"1.2.3.4"``)
            :param int port: The tcp port of the peer

            Note:
                The peer address is store 15 minutes
        """
        if (
            port > 0 and
            ip not in self.ignored_ip and
            not utils.ip_in_nets(ip, self.ignored_net)
        ):
            self._got_peers[info_hash][(ip,port)]=time.time()
            # we only keep at most 1000 peers per hash
            if len(self._got_peers[info_hash]) > 1000:
                self._got_peers[info_hash].popitem(False)

    def get_peers(self, hash, delay=0, block=True, callback=None, limit=10):
        """
            Return a list of at most 1000 (ip, port) downloading ``hash`` or pass-it to ``callback``

            :param bytes hash: A 160bits (20 Bytes) long identifier to look for peers
            :param float delay: A delay in second to wait before starting to look for the K closest
                nodes into the dht. The default is ``0``
            :param bool block: If ``True`` (the default) block until we get at least one peer,
                otherwise, return immediately (with or without peers).
            :param callback: An optional callable taking as argument a list of peers (ip, port).
                Called once we found most of the peers store in the DHT.
            :param int limit: The maximum number of peer to look for before stoping the search.
                The default is 10, the max is 1000.
            :return: A list of peers (ip, port) with the ip in dotted notation (``"1.2.3.4"``)
            :rtype: list

            Note:
                if ``block`` is False, the returned list will be most likely empty on the first call
                subsequent call will return peers found so far.
        """
        peers = None
        if hash in self._got_peers and self._got_peers[hash] and len(self._got_peers[hash])>=limit:
            peers = self._get_peers(hash, compact=False)
            if callback:
                callback(peers)
            return peers
        elif hash in self._get_peer_loop_lock:
            if block:
                while hash in self._get_peer_loop_lock and not self.stoped:
                    peers = self._get_peers(hash, compact=False)
                    if peers:
                        break
                    self.sleep(0.1)
            return peers
        else:
            self._get_peer_loop_lock[hash]=time.time()
            self.debug(2, "get peers hash %s" % binascii.b2a_hex(hash))
            self.root.register_torrent(hash)
            tried_nodes = set()
            ts = time.time() + delay
            closest = self.get_closest_nodes(hash)
            typ = "peers"
            heapq.heappush(self._get_peer_loop_list, (ts, hash, tried_nodes, closest, typ, callback, limit))
            if block:
                while hash in self._get_peer_loop_lock and not self.stoped:
                    peers = self._get_peers(hash, compact=False)
                    if peers:
                        break
                    self.sleep(0.1)
            return peers

    def _get_peers_closest_loop(self):
        """
            Weigthless thread dealing we the :attr:`_get_peer_loop_list` heapq. Its execution
            is handled by :attr:`_scheduler` of type :class:`utils.Scheduler`
        """
        yield 0
        def on_stop(hash, typ):
            self.root.release_torrent(hash)
            if typ == "peers":
                try: del self._get_peer_loop_lock[hash]
                except KeyError: pass
            elif typ == "closest":
                try: del self._get_closest_loop_lock[hash]
                except KeyError: pass

        def stop():
            while self._get_peer_loop_list:
                (_, hash, _, _, typ, _, _) = heapq.heappop(self._get_peer_loop_list)
                on_stop(hash, typ)

        while True:
            tosleep = 1
            while self._get_peer_loop_list:
                if self.stoped:
                    stop()
                    return
                # fetch next hash to process
                (ts, hash, tried_nodes, closest, typ, callback, limit) = heapq.heappop(self._get_peer_loop_list)
                if typ not in ["peers", "closest"]:
                    raise ValueError("typ should not be %s" % typ)
                # if process time is in the past process it
                if ts <= time.time():
                    # get hash k closest node that have not been tried
                    _closest = self.get_closest_nodes(hash)
                    __closest = [node for node in _closest if node not in tried_nodes]

                    if __closest:
                        # alpha = 3 from the kademlia paper
                        nodes = __closest[0:3]
                        # send a get peer to the 3 closest nodes
                        for node in nodes:
                            node.get_peers(self, hash)
                            tried_nodes.add(node)
                        ts = time.time() + 2
                        # we search peers and we found as least limit of them
                        if (typ == "peers" and limit and hash in self._got_peers and self._got_peers[hash] and len(self._got_peers[hash])>=limit):
                            self.debug(2, "Hash %s find peers" % binascii.b2a_hex(hash))
                            if callback:
                                callback(self._get_peers(hash, compact=False))
                            on_stop(hash, typ)
                        # we search closest node and we don't find any closest
                        elif (typ == "closest" and closest == _closest):
                            self.debug(2, "Hash %s find nodes" % binascii.b2a_hex(hash))
                            if callback:
                                callback(_closest)
                            on_stop(hash, typ)
                        # Else had it the the heap to be processed later
                        else:
                            heapq.heappush(self._get_peer_loop_list, (ts, hash, tried_nodes, _closest, typ, callback, limit))
                        del node
                        del ts
                    else:
                        # we search peers, and we found some
                        if (typ == "peers" and hash in self._got_peers and self._got_peers[hash]):
                            self.debug(2, "Hash %s find peers" % binascii.b2a_hex(hash))
                            if callback:
                                callback(self._get_peers(hash, compact=False))
                            on_stop(hash, typ)
                        # we did not found peers nor closest node althougth we ask every close nodes we know of
                        else:
                            self.debug(2, "Hash %s not peers or nodes not found" % binascii.b2a_hex(hash))
                            if callback:
                                callback([])
                            on_stop(hash, typ)
                    del _closest
                    del __closest
                else:
                    # if fetch time in the future, sleep until that date
                    tosleep = max(1, ts - time.time())
                    heapq.heappush(self._get_peer_loop_list, (ts, hash, tried_nodes, closest, typ, callback, limit))
                    break
                del tried_nodes
                del closest
            yield (time.time() + tosleep)

    def _get_peers(self, info_hash, compact=True, errno=0):
        """
            Return peers store locally by remote announce_peer queries

            :param bytes info_hash: A 160 bits (20 Bytes) long identifier for which we want to get
                peers
            :param bool compact: If ``True`` the peers addresses are returned in compact format
                Otherwise, the peers addresses are tuple (ip, port) with ip in dotted notation
                (``"1.2.3.4"``) and port an integer. The default is ``True``.
            :return: A list of peers addresses
            :rtype: list
            :raises KeyError: if no peers for ``info_hash`` are store locally

            Note:
                If not peer are found for ``info_hash``, the function will retry for 2s before
                raising a KeyError exception.

                Contact information in for peers is encoded as a 6-byte string.
                Also known as "Compact IP-address/port info" the 4-byte IP address
                is in network byte order with the 2 byte port in network byte order
                concatenated onto the end.
        """
        if not info_hash in self._peers and compact:
            return None
        elif not info_hash in self._got_peers and not compact:
            return None
        else:
           try:
               # In compact mode (to send over udp) return at most 70 peers to avoid udp fragmentation
               if compact:
                   peers = [(-t,ip,port) for ((ip, port), t) in six.iteritems(self._peers[info_hash])]
                   # putting the more recent annonces in first
                   peers.sort()
                   return [struct.pack("!4sH", socket.inet_aton(ip), port) for (_, ip, port) in peers[0:70]]
               else:
                   peers = [(-t,ip,port) for ((ip, port), t) in six.iteritems(self._got_peers[info_hash])]
                   # putting the more recent annonces in first
                   peers.sort()
                   return [(ip, port) for (_, ip, port) in peers]
           except KeyError:
               if errno > 20:
                   raise
               time.sleep(0.1)
               return self._get_peers(info_hash, compact, errno=errno+1)

    def get_closest_nodes(self, id, compact=False):
        """
        return the current K closest nodes from ``id`` present in the routing table (K = 8)

        :param bytes id:  A 160bits (20 Bytes) long identifier for which we want the closest nodes
            in the routing table.
        :param bool compact: If ``True`` the nodes infos are returned in compact format.
            Otherwise, intances of :class:`Node` are returned. The default is ``False``.
        :return: A list of :class:`Node` if ``compact`` is ``False``, a :class:`bytes` of size
            multiple of 26 if ``compact`` is ``True``.
        :rtype: :class:`list` if ``compact`` is ``False``, a :class:`bytes` otherwise.

        Note:
            Contact information for peers is encoded as a 6-byte string.
            Also known as "Compact IP-address/port info" the 4-byte IP address
            is in network byte order with the 2 byte port in network byte order
            concatenated onto the end.

            Contact information for nodes is encoded as a 26-byte string.
            Also known as "Compact node info" the 20-byte Node ID in network byte
            order and the compact IP-address/port info concatenated to the end.
        """
        l = list(self.root.get_closest_nodes(id))
        if compact:
            return b"".join(n.compact_info() for n in l)
        else:
            return list(self.root.get_closest_nodes(id))

    def bootstarp(
        self,
        addresses=[
            ("router.utorrent.com", 6881), ("grenade.genua.fr", 6880), ("dht.transmissionbt.com", 6881)
        ]
    ):
        """
            Boostrap the DHT to some wellknown nodes

            :param list addresses: A list of couple (node addresse, node ip). The default the list
                of the following nodes
                    * router.utorrent.com:6881
                    * dht.transmissionbt.com:6881
                    * grenade.genua.fr:6880
        """
        self.debug(0,"Bootstraping")
        for addr in addresses:
            msg = BMessage()
            msg.y = b'q'
            msg.q = b"find_node"
            self._set_transaction_id(msg)
            msg.set_a(True)
            msg[b"id"] = self.myid.value
            msg[b"target"] = self.myid.value
            self.sendto(msg.encode(), addr)



    def _update_node(self, obj):
        """
            Update a node the in routing table on msg receival, especially its
            :attr:`Node.last_query` :attr:`Node.last_response` and :attr:`Node.failed` attributes

            :param brcp.BMessage obj: A reived message
        """
        if obj.y == b"q" or obj.y == b"r":
            id = obj.get(b"id")
            if id:
                try:
                    node = self.root.get_node(id)
                    node.ip = obj.addr[0]
                    node.port = obj.addr[1]
                except NotFound:
                    node = Node(id=id, ip=obj.addr[0], port=obj.addr[1])
                    self.root.add(self, node)
                if obj.y == b"q":
                    node.last_query = int(time.time())
                elif obj.y == b"r":
                    node.last_response = int(time.time())
                    node.failed = 0
            else:
                self.debug(1, "obj without id, no node update")
        else:
            self.debug(2, "obj of type %r" % obj.y)

    def sendto(self, msg, addr):
        """
            Program a msg to be send over the network

            :param bytes msg: The message to send
            :param tuple addr: A couple (ip, port) to send the message to. ip is in dotted notation

            Notes:
                The message is push to the :attr:`to_send` queue.
        """
        self.to_send.put((msg, addr))

    def _process_outgoing_message(self):
        """
            Process a new outgoing message. The message is retrieved from the queue :attr:`to_send`
            and send to :attr:`sock`. So the method should only be called then there is a message
            in the send queue and then :attr:`sock` is ready for a write.
        """
        try:
            (msg, addr) = self.to_send.get_nowait()
            try:
                self.sock.sendto(msg, addr)
                self._socket_out+=1
            except socket.gaierror as e:
                self.debug(0, "send:%r %r %r" % (e, addr, msg))
            except socket.error as e:
                # 90: Message too long
                # 13: Permission denied
                if e.errno in [90, 13]:
                    self.debug(0, "send:%r %r %r" % (e, addr, msg))
                # 11: Resource temporarily unavailable, try again
                #  1: Operation not permitted
                elif e.errno in [11, 1]:
                    pass
                else:
                    self.debug(0, "send:%r %r" % (e, addr) )
                    raise
        except Queue.Empty:
            pass

    def _process_incoming_message(self):
        """
            Process a new incoming message. The message is read from :attr:`sock`, so this
            method should only be called when :attr:`sock` is ready for a read.

        """
        try:
            data, addr = self.sock.recvfrom(4048)
            if addr[0] in self.ignored_ip:
                return
            elif utils.ip_in_nets(addr[0], self.ignored_net):
                return
            elif addr[1] < 1 or addr[1] > 65535:
                self.debug(1, "Port should be whithin 1 and 65535, not %s" % addr[1])
                return
            elif len(data) < 20:
                return
            else:
                # Building python object from bencoded data
                obj, obj_opt = self._decode(data, addr)
                # Update sender node in routing table
                try:
                    self._update_node(obj)
                except TypeError:
                    print("TypeError: %r in _recv_loop" % obj)
                    raise
                # On query
                if obj.y == b"q":
                    # process the query
                    self._process_query(obj)
                    # build the response object
                    reponse = obj.response(self)

                    self._socket_in+=1
                    self.last_msg = time.time()

                    # send it
                    self.sendto(reponse.encode(), addr)
                # on response
                elif obj.y == b"r":
                    # process the response
                    try:
                        self._process_response(obj, obj_opt)
                    except ValueError as error:
                        raise ProtocolError(obj.t, error.args[0])

                    self._socket_in+=1
                    self.last_msg = time.time()
                    self.last_msg_rep = time.time()
                # on error
                elif obj.y == b"e":
                    # process it
                    self._process_error(obj, obj_opt)
        # if we raised a BError, send it
        except (BError,) as error:
            if self.debuglvl > 1:
                traceback.print_exc()
                self.debug(2, "error %r" % error)
            self.sendto(error.encode(), addr)
        # socket unavailable ?
        except socket.error as e:
            if e.errno not in [11, 1]: # 11: Resource temporarily unavailable
                self.debug(0, "send:%r : (%r, %r)" % (e, data, addr))
                raise
        except MissingT:
            pass
        except DecodeError:
            pass
        except TransactionIdUnknown:
            pass
        except ValueError as e:
            #if self.debuglvl > 0:
            #    traceback.print_exc()
            #    self.debug(1, "%s for %r" % (e, addr))
            traceback.print_exc()
            #self.debug(-100, e.args[0])



    cdef void _set_transaction_id(self, BMessage query, int id_len=6):
        """
            Set the transaction id (key t of the dictionnary) on a query

            :param krcp.BMessage query: A query message
            :param int id_len: The len of the generated transaction id. The default is 6.

            Notes:
                In case of collision with a already generated id, ``_set_transaction_id`` is
                called again, incrementing ``id_len``.
        """
        id = os.urandom(id_len)
        if id in self.transaction_type:
            self._set_transaction_id(query, id_len=id_len+1)
        self.transaction_type[id] = (None, time.time(), query)
        query.set_t(id, id_len)

    def _get_token(self, ip):
        """
            Return a token for ``ip``

            :param str ip: A ip address in dotted notation
            :return: A random id of lendth 4
            :rtype: bytes

            Notes:
                Generate at most 1 new token by ip every 5 min. A token is considered valid
                until 10 min after it has been generated.

        """
        if ip in self.token and self.token[ip][-1][1] < 300:
            return self.token[ip][-1][0]
        else:
            id = os.urandom(4)
            self.token[ip].append((id, time.time()))
            return id

    def _get_valid_token(self, ip):
        """
            Return a list of valid tokens for ``ip``

            :param str ip: A ip address in dotted notation
            :return: A list of valid tokens for ``ip``
            :rtype: list
        """
        if ip in self.token:
            now = time.time()
            return [t[0] for t in self.token[ip] if (now - t[1]) < 600]
        else:
            return []

    def clean(self):
        """Function called every 15s to do some cleanning. It can safely be overload"""
        pass
    def clean_long(self):
        """Function called every 15min to do some cleanning. It can safely be overload"""
        pass

    def _clean(self):
        """
            Function cleaning datastructures of the DHT

            The following cleaning is done every 15 seconds
                * delete entries from :attr:`transaction_type` (query without response) older than
                  30 seconds
                * Remove dead threads from :attr:`_threads`
                * If no message has been received since more than 2 minutes, stop the DHT
                * If no response to our query has been received since more than 5 minutes,
                  stop the DHT
                * call the :meth:`clean` method

            The following cleaning is done every 15 minutes
                * delete expired tokens (older than 10 min) from :attr:`token`
                * delete received token older than 10 min from :attr:`mytoken`
                * delete peers not annonced since more than 30min from :attr:`_peers`
                * delete peers from get_peer response older than 15min from :attr:`_got_peers`
                * call the :meth:`clean_long` method
        """
        now = time.time()

        to_delete = []
        for id in self.transaction_type:
            if now - self.transaction_type[id][1] > 30:
                to_delete.append(id)
        for key in to_delete:
            del self.transaction_type[key]

        self._threads = [t for t in self._threads[:] if t.is_alive()]

        if now - self.last_msg > 2 * 60:
            self.debug(-10, "No msg since more than 2 minutes on udp port %d" % self.bind_port)
            self.stop()
        elif now - self.last_msg_rep > 5 * 60:
            self.debug(
                -10,
                "No msg response since more than 5 minutes on udp port %d" % self.bind_port
            )
            self.stop()

        self.clean()

        # Long cleaning
        if now - self._long_clean >= 15 * 60:
            # cleaning old tokens
            to_delete = []
            for ip in self.token:
                self.token[ip] = [t for t in self.token[ip] if (now - t[1]) < 600]
                if not self.token[ip]:
                    to_delete.append(ip)
            for key in to_delete:
                del self.token[key]
            to_delete = []
            for id in self.mytoken:
                try:
                    if now - self.mytoken[id][1] > 600:
                        to_delete.append(id)
                except KeyError:
                    pass
            for key in to_delete:
                try:
                    del self.mytoken[id]
                except KeyError:
                    pass

            # cleaning old peer for announce_peer
            to_delete = collections.defaultdict(list)
            for hash, peers in six.iteritems(self._peers):
                for peer in peers:
                    try:
                        if now - self._peers[hash][peer] > 30 * 60:
                            to_delete[hash].append(peer)
                    except KeyError:
                        pass
            for hash in to_delete:
                for peer in to_delete[hash]:
                    try:
                        del self._peers[hash][peer]
                    except KeyError:
                        pass
                if not self._peers[hash]:
                    del self._peers[hash]

            to_delete = collections.defaultdict(list)
            for hash, peers in six.iteritems(self._got_peers):
                for peer in peers:
                    try:
                        if now - self._got_peers[hash][peer] > 15 * 60:
                            to_delete[hash].append(peer)
                    except KeyError:
                        pass
            for hash in to_delete:
                for peer in to_delete[hash]:
                    try:
                        del self._got_peers[hash][peer]
                    except KeyError:
                        pass
                if not self._got_peers[hash]:
                    del self._got_peers[hash]

            self.clean_long()

            self._long_clean = now

    def build_table(self):
        """Build the routing table by querying find_nodes on the dht own id :attr:`myid`"""
        nodes = self.get_closest_nodes(self.myid)
        for node in nodes:
            node.find_node(self, self.myid)
        return bool(nodes)

    def _routine(self):
        """
            Weigthless thread performing some routine (boostraping, building the routing table,
            cleaning) on the DHT
        """
        yield 0
        next_routine = time.time() + 15
        while True:
            if self.stoped:
                return
            yield next_routine
            now = time.time()
            next_routine = now + 15

            # calling clean every 15s
            self._clean()

            # Searching its own id while the Routing table is growing
            if self._root_heigth != self.root.heigth():
                self.debug(1, "Fetching my own id")
                if self.build_table():
                    self._root_heigth = self.root.heigth()

            # displaying some stats
            (in_s, out_s, delta) = self._socket_stats()
            if in_s <= 0 or self.debuglvl > 0:
                (nodes, goods, bads) = self.root.stats()
                if goods <= 0:
                    self.bootstarp()
                    next_routine = now + 1
                self.debug(
                    0 if in_s <= 0 and out_s > 0 and goods < 20 else 1,
                    "%d nodes, %d goods, %d bads | in: %s, out: %s en %ss" % (
                        nodes, goods, bads, in_s, out_s, int(delta)
                    )
                )


    def register_message(self, msg):
        """
            Register a dht message to be processed by the following user defined functions
                * :meth:`on_error`
                * :meth:`on_ping_query`
                * :meth:`on_ping_response`
                * :meth:`on_find_node_query`
                * :meth:`on_find_node_response`
                * :meth:`on_get_peers_query`
                * :meth:`on_get_peers_response`
                * :meth:`on_announce_peer_query`
                * :meth:`on_announce_peer_response`
                * ...

            :param bytes msg: A dht message to register like ``b'error'``, ``b'ping'``,
                ``b'find_node'``, ``b'get_peers'`` or ``b'announce_peer'``

            Note:
              * on query reception, the function on_``msg``_query will be call with the
                query as parameter
              * on response reception, the function on_``msg``_response will be called with
                the query and the response as parameters
              * on error reception, the function ``on_error`` will be called with the error and
                the query as parameter
              * The message kind is in the ``q`` key of any dht query message

        Args:
          msg (str): a dht message type like ping, find_node, get_peers or announce_peer
        """
        self._to_process_registered.add(msg)

    def on_error(self, error, query=None):
        """
            Function called then a query has be responded by an error message.
            Can safely the overloaded.

            :param krcp.Berror error: An error instance
            :param krcp.BMessage query: An optional query raising the error message

            Notes:
                For this function to be called on error reception, you need to call
                :meth:`register_message` with the parameter ``b'error'``
        """
        pass
    def on_ping_response(self, query, response):
        """
            Function called on a ping response reception. Can safely the overloaded

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object

            Notes:
                For this function to be called on ping response reception, you need to call
                :meth:`register_message` with the parameter ``b'ping'``
        """
        pass
    def on_find_node_response(self, query, response):
        """
            Function called on a find_node response reception. Can safely the overloaded

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object

            Notes:
                For this function to be called on find_node response reception, you need to call
                :meth:`register_message` with the parameter ``b'find_node'``
        """
        pass
    def on_get_peers_response(self, query, response):
        """
            Function called on a get_peers response reception. Can safely the overloaded

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object

            Notes:
                For this function to be called on get_peers response reception, you need to call
                :meth:`register_message` with the parameter ``b'get_peers'``
        """
        pass
    def on_announce_peer_response(self, query, response):
        """
            Function called on a announce_peer response reception. Can safely the overloaded

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object

            Notes:
                For this function to be called on announce_peer response reception, you need to call
                :meth:`register_message` with the parameter ``b'announce_peer'``
        """
        pass
    def on_ping_query(self, query):
        """
            Function called on a ping query reception. Can safely the overloaded

            :param krcp.BMessage query: the received query object

            Notes:
                For this function to be called on ping query reception, you need to call
                :meth:`register_message` with the parameter ``b'ping'``
        """
        pass
    def on_find_node_query(self, query):
        """
            Function called on a find_node query reception. Can safely the overloaded

            :param krcp.BMessage query: the received query object

            Notes:
                For this function to be called on find_node query reception, you need to call
                :meth:`register_message` with the parameter ``b'find_node'``
        """
        pass
    def on_get_peers_query(self, query):
        """
            Function called on a get_peers query reception. Can safely the overloaded

            :param krcp.BMessage query: the received query object

            Notes:
                For this function to be called on get_peers query reception, you need to call
                :meth:`register_message` with the parameter ``b'get_peers'``
        """
        pass
    def on_announce_peer_query(self, query):
        """
            Function called on a announce query reception. Can safely the overloaded

            :param krcp.BMessage query: the received query object

            Notes:
                For this function to be called on announce_peer query reception, you need to call
                :meth:`register_message` with the parameter ``b'announce_peer'``
        """
        pass
    def _on_ping_response(self, query, response):
        """
            Function called on a ping response reception, do not overload, use
            :meth:`on_ping_response` instead.

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object
        """
        pass
    def _on_find_node_response(self, query, response):
        """
            Function called on a find_node response reception, do not overload, use
            :meth:`find_node_response` instead.

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object
        """
        nodes = Node.from_compact_infos(response.get(b"nodes", b""))
        for node in nodes:
            try:
                self.root.add(self, node)
            except AttributeError:
                print("AttributeError: %r in _on_find_node_response" % node)
                raise
        self.debug(2, "%s nodes added to routing table" % len(nodes))
    def _on_get_peers_response(self, query, response):
        """
            Function called on a get_peers response reception, do not overload, use
            :meth:`on_get_peers_response` instead.

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object
        """
        token = response.get(b"token")
        if token:
            self.mytoken[response[b"id"]]=(token, time.time())
        for node in Node.from_compact_infos(response.get(b"nodes", "")):
            self.root.add(self, node)
        for ipport in response.get(b"values", []):
            (ip, port) = struct.unpack("!4sH", ipport)
            ip = socket.inet_ntoa(ip)
            self._add_peer_queried(query[b"info_hash"], ip=ip, port=port)
    def _on_announce_peer_response(self, query, response):
        """
            Function called on a announce_peer response reception, do not overload, use
            :meth:`on_announce_peer_response` instead.

            :param krcp.BMessage query: the sent query object
            :param krcp.BMessage response: the received response object
        """
        pass

    def _on_ping_query(self, query):
        """
            Function called on a ping query reception, do not overload, use
            :meth:`on_ping_query` instead.

            :param krcp.BMessage query: the received query object
        """
        pass
    def _on_find_node_query(self, query):
        """
            Function called on a find_node query reception, do not overload, use
            :meth:`on_find_node_query` instead.

            :param krcp.BMessage query: the received query object
        """
        pass
    def _on_get_peers_query(self, query):
        """
            Function called on a get_peers query reception, do not overload, use
            :meth:`on_get_peers_query` instead.

            :param krcp.BMessage query: the received query object
        """
        pass
    def _on_announce_peer_query(self, query):
        """
            Function called on a announce_peer query reception, do not overload, use
            :meth:`on_announce_peer_query` instead.

            :param krcp.BMessage query: the received query object
        """
        try:
            if query.get(b"implied_port", 0) != 0:
                if query.addr[1] > 0 and query.addr[1] < 65536:
                    self._add_peer(
                        info_hash=query[b"info_hash"],
                        ip=query.addr[0],
                        port=query.addr[1]
                    )
                else:
                    self.debug(
                        1,
                        "Invalid port number on announce %s, sould be within 1 and 65535" % (
                            query.addr[1],
                        )
                    )
            else:
                if query[b"port"] > 0 and query[b"port"] < 65536:
                    self._add_peer(
                        info_hash=query[b"info_hash"],
                        ip=query.addr[0],
                        port=query[b"port"]
                    )
                else:
                    self.debug(
                        1,
                        "Invalid port number on announce %s, sould be within 1 and 65535" % (
                            query["port"],
                        )
                    )
        except KeyError as e:
            raise ProtocolError(query.t, b"Message malformed: %s key is missing" % e.args[0])

    def _process_error(self, obj, query):
        if "error" in self._to_process_registered:
            try:
                self._to_process.put_nowait((query, obj))
            except Queue.Full:
                self.debug(0, "Unable to queue msg to be processed, QueueFull")

    def _process_response(self, obj, query):
        if query.q in [b"find_node", b"ping", b"get_peers", b"announce_peer"]:
            getattr(self, '_on_%s_response' % query.q.decode())(query, obj)
        if query.q in self._to_process_registered:
            try:
                self._to_process.put_nowait((query, obj))
            except Queue.Full:
                self.debug(0, "Unable to queue msg to be processed, QueueFull")

    def _process_query(self, obj):
        if obj.q in [b"find_node", b"ping", b"get_peers", b"announce_peer"]:
            getattr(self, '_on_%s_query' % obj.q.decode())(obj)
        if obj.q in self._to_process_registered:
            try:
                self._to_process.put_nowait((obj, None))
            except Queue.Full:
                self.debug(0, "Unable to queue msg to be processed, QueueFull")

    def _process_loop(self):
        """function lauch by the thread processing messages"""
        yield 1
        yield self._to_process
        while True:
            if self.stoped:
                return
            try:
                (query, response) = self._to_process.get_nowait()
                if response is None:
                    getattr(self, 'on_%s_query' % query.q.decode())(query)
                elif response.y == b"e":
                    self.on_error(response, query)
                else:
                    getattr(self, 'on_%s_response' % query.q.decode())(query, response)
            except Queue.Empty:
                pass
            yield

    def _decode(self, s, addr):
        """
            decode a message

            :param bytes s: A newly received message
            :param tuple addr: A couple (ip, port) with ip in dotted notation
            :return A couple (decoded message, query) if the message is a response or an error,
                (decoded message, None) otherwise
            :rtype: tuple
        """
        msg = BMessage(addr=addr, debug=self.debuglvl)
        msg.decode(s, len(s))
        try:
            if msg.y == b"q":
                return msg, None
            elif msg.y == b"r":
                if msg.t in self.transaction_type:
                    ttype = self.transaction_type[msg.t][0]
                    query = self.transaction_type[msg.t][2]
                    return msg, query
                else:
                    raise TransactionIdUnknown(msg.t)
            elif msg.y == b"e":
                query = self.transaction_type.get(msg.t, (None, None, None))[2]
                if msg.errno == 201:
                    self.debug(2, "ERROR:201:%s pour %r" % (msg.errmsg, self.transaction_type.get(msg.t, {})))
                    return GenericError(msg.t, msg.errmsg), query
                elif msg.errno == 202:
                    self.debug(2, "ERROR:202:%s pour %r" % (msg.errmsg, self.transaction_type.get(msg.t, {})))
                    return ServerError(msg.t, msg.errmsg), query
                elif msg.errno == 203:
                    t = self.transaction_type.get(msg.t)
                    self.debug(1 if t else 2, "ERROR:203:%s pour %r" % (msg.errmsg, t))
                    return ProtocolError(msg.t, msg.errmsg), query
                elif msg.errno == 204:
                    t = self.transaction_type.get(msg.t)
                    self.debug(0 if t else 1, "ERROR:204:%s pour %r" % (msg.errmsg, t))
                    return MethodUnknownError(msg.t, msg.errmsg), query
                else:
                    self.debug(3, "ERROR:%s:%s pour %r" % (msg.errno, msg.errmsg, self.transaction_type.get(msg.t, {})))
                    raise MethodUnknownError(msg.t, b"Error code %s unknown" % msg.errno)
            else:
                raise ValueError("UNKNOWN MSG: %r decoded as %r from %r" % (s, msg, addr))
        except KeyError as e:
            raise ProtocolError(msg.t, b"Message malformed: %s key is missing" % e.args[0])
        except IndexError:
            raise ProtocolError(msg.t, b"Message malformed")


class BucketFull(Exception):
    pass

class BucketNotFull(Exception):
    pass

class NoTokenError(Exception):
    pass

class FailToStop(Exception):
    pass

class TransactionIdUnknown(Exception):
    pass

cdef class Node:
    """
        A node of the dht in the routing table

        :param bytes id: The 160 bits (20 Bytes) long identifier of the node
        :param str ip: The ip, in dotted notation of the node
        :param int port: The udp dht port of the node
        :param int last_response: Unix timestamp of the last received response from this node
        :param int last_query: Unix timestamp of the last received query from this node
        :param int failed: Number of consecutive queries sended to the node without responses

        Note:
          A good node is a node has responded to one of our queries within the last
          15 minutes. A node is also good if it has ever responded to one of our
          queries and has sent us a query within the last 15 minutes. After 15 minutes
          of inactivity, a node becomes questionable. Nodes become bad when they fail
          to respond to multiple queries in a row (3 query in a row in this implementation).
    """
    #: 160bits (20 Bytes) identifier of the node
    cdef char _id[20]
    #: ip address of the node, encoded on 4 bytes
    cdef char _ip[4]
    #: The udp port of the node
    cdef int _port
    #: Unix timestamp of the last received response from this node
    cdef int _last_response
    #: Unix timestamp of the last received query from this node
    cdef int _last_query
    #: number of reponse pending (increase on sending query to the node, set to 0 on reception from
    #: the node)
    cdef int _failed

    def __init__(self, bytes id, ip, int port, int last_response=0, int last_query=0, int failed=0):
        cdef char* cip
        cdef char* cid
        if ip[0] == u'0':
            raise ValueError("IP start with 0 *_* %r %r" % (ip, self._ip[:4]))
        tip = socket.inet_aton(ip)
        cip = tip
        id = ID.to_bytes(id)
        cid = id
        with nogil:
            if not port > 0 and port < 65536:
                with gil:
                    raise ValueError("Invalid port number %s, sould be within 1 and 65535 for %s" % (port, ip))
            #self._id = <char*>malloc(20 * sizeof(char))
            strncpy(self._id, cid, 20)
            #self._ip = <char*>malloc(4  * sizeof(char))
            strncpy(self._ip, cip, 4)
            self._port = port
            self._last_response = last_response
            self._last_query = last_query
            self._failed = failed


    def __richcmp__(self, Node other, int op):
            if op == 2: # ==
                return other.id == self.id
            elif op == 3: # !=
                return other.id != self.id
            elif op == 0: # <
                return max(self.last_response, self.last_query) < max(other.last_response, other.last_query)
            elif op == 4: # >
                return not (max(self.last_response, self.last_query) < max(other.last_response, other.last_query)) and not (other.id == self.id)
            elif op == 1: # <=
                return max(self.last_response, self.last_query) < max(other.last_response, other.last_query) or (other.id == self.id)
            elif op == 5: # >=
                return not (max(self.last_response, self.last_query) < max(other.last_response, other.last_query))
            else:
                return False

    #: udp port of the node
    property port:
        def __get__(self):return self._port
        def __set__(self, int i):self._port = i
    #: Unix timestamp of the last received response from this node
    property last_response:
        def __get__(self):return self._last_response
        def __set__(self, int i):self._last_response = i
    #: Unix timestamp of the last received query from this node
    property last_query:
        def __get__(self):return self._last_query
        def __set__(self, int i):self._last_query = i
    #: number of reponse pending (increase on sending query to the node, set to 0 on reception from
    #: the node)
    property failed:
        def __get__(self):return self._failed
        def __set__(self, int i):self._failed = i
    #: 160bits (20 Bytes) identifier of the node
    property id:
        def __get__(self):
            return self._id[:20]
    #: ``True`` if the node is a good node. A good node is a node has responded to one of our
    #: queries within the last 15 minutes. A node is also good if it has ever responded to one of
    #: our queries and has sent us a query within the last 15 minutes.
    property good:
        def __get__(self):
            now = time.time()
            # A good node is a node has responded to one of our queries within the last 15 minutes.
            # A node is also good if it has ever responded to one of our queries and has sent us a query within the last 15 minutes.
            return ((now - self.last_response) < 15 * 60) or (self.last_response > 0 and (now - self.last_query) < 15 * 60)

    #: ``True`` if the node is a bad node (communication with the node is not possible). Nodes
    #: become bad when they fail to respond to 3 queries in a row.
    property bad:
        def __get__(self):
            # Nodes become bad when they fail to respond to multiple queries in a row.
            return not self.good and self.failed > 3

    #: ip address of the node in dotted notation
    property ip:
        def __get__(self):
            ip = socket.inet_ntoa(self._ip[:4])
            if ip[0] == '0':
                raise ValueError("IP start with 0 *_* %r %r" % (ip, self._ip[:4]))
            return ip
        def __set__(self, ip):
            cdef char* cip
            if ip[0] == u'0':
                raise ValueError("IP start with 0 *_* %r %r" % (ip, self._ip[:4]))
            tip = socket.inet_aton(ip)
            cip = tip
            with nogil:
                strncmp(self._ip, cip, 4)

    def __repr__(self):
        return "Node: %s:%s" % (self.ip, self.port)

    def compact_info(self):
        """
            Return the compact contact information of the node

            Notes:
                Contact information for peers is encoded as a 6-byte string.
                Also known as "Compact IP-address/port info" the 4-byte IP address
                is in network byte order with the 2 byte port in network byte order
                concatenated onto the end.
                Contact information for nodes is encoded as a 26-byte string.
                Also known as "Compact node info" the 20-byte Node ID in network byte
                order has the compact IP-address/port info concatenated to the end.
        """
        return struct.pack("!20s4sH", self.id, self._ip, self.port)

    @classmethod
    def from_compact_infos(cls, infos):
        """
            Instancy nodes from multiple compact node information string

            :param bytes infos: A string of size multiple of 26
            :return: A list of :class:`Node` instances
            :rtype: list

            Notes:
                Contact information for peers is encoded as a 6-byte string.
                Also known as "Compact IP-address/port info" the 4-byte IP address
                is in network byte order with the 2 byte port in network byte order
                concatenated onto the end.
                Contact information for nodes is encoded as a 26-byte string.
                Also known as "Compact node info" the 20-byte Node ID in network byte
                order has the compact IP-address/port info concatenated to the end.
        """
        nodes = []
        length = len(infos)
        if length//26*26 != length:
            raise ValueError(b"nodes length should be a multiple of 26")
        i=0
        while i < length:
            if infos[i+20:i+24] != b'\0\0\0\0' and infos[i+24:i+26] != b'\0\0':
                #try:
                    nodes.append(Node.from_compact_info(infos[i:i+26]))
                #except ValueError as e:
                #    print("%s %s" % (e, v))
            i += 26
        return nodes

    @classmethod
    def from_compact_info(cls, info):
        """
            Instancy a node from its compact node infoformation string

            :param bytes info: A string of length 26
            :return: A node instance
            :rtype: Node

            Notes:
                Contact information for peers is encoded as a 6-byte string.
                Also known as "Compact IP-address/port info" the 4-byte IP address
                is in network byte order with the 2 byte port in network byte order
                concatenated onto the end.
                Contact information for nodes is encoded as a 26-byte string.
                Also known as "Compact node info" the 20-byte Node ID in network byte
                order has the compact IP-address/port info concatenated to the end.
        """
        if len(info) != 26:
            raise EnvironmentError("compact node info should be 26 chars long")
        (id, ip, port) = struct.unpack("!20s4sH", info)
        ip = socket.inet_ntoa(ip)
        #id = ID(id)
        return cls(id, ip, port)



    def __cmp__(self, Node other):
        if self.__richcmp__(other, 0):
            return -1
        elif self.__richcmp__(other, 2):
            return 0
        else:
            return 1

    def __hash__(self):
        return hash(self.id)

    def ping(self, DHT_BASE dht):
        """
            Send a ping query to the node

            :param DHT_BASE dht: The dht instance to use to send the message
        """
        id = dht.myid.value
        msg = BMessage()
        dht._set_transaction_id(msg)
        msg.set_y("q", 1)
        msg.set_q("ping", 4)
        msg.set_a(True)
        msg.set_id(id, len(dht.myid))
        self._failed+=1
        dht.sendto(msg.encode(), (self.ip, self.port))

    def find_node(self, DHT_BASE dht, target):
        """
            Send a find_node query to the node

            :param DHT_BASE dht: The dht instance to use to send the message
            :param bytes target: the 160bits (20 bytes) target node id
        """
        id = dht.myid.value
        target = ID.to_bytes(target)
        tl = len(target)
        msg = BMessage()
        dht._set_transaction_id(msg)
        msg.set_y("q", 1)
        msg.set_q("find_node", 9)
        msg.set_a(True)
        msg.set_id(id, len(dht.myid))
        msg.set_target(target, tl)
        self._failed+=1
        dht.sendto(msg.encode(), (self.ip, self.port))

    def get_peers(self, DHT_BASE dht, info_hash):
        """
            Send a get_peers query to the node

            :param DHT_BASE dht: The dht instance to use to send the message
            :param bytes info_hash: a 160bits (20 bytes) torrent id
        """
        id = dht.myid.value
        info_hash = ID.to_bytes(info_hash)
        ihl = len(info_hash)
        msg = BMessage()
        dht._set_transaction_id(msg)
        msg.set_y("q", 1)
        msg.set_q("get_peers", 9)
        msg.set_a(True)
        msg.set_id(id, len(dht.myid))
        msg.set_info_hash(info_hash, ihl)
        self._failed+=1
        dht.sendto(msg.encode(), (self.ip, self.port))

    def announce_peer(self, DHT_BASE dht, info_hash, int port):
        """
            Send a announce_peer query to the node

            :param DHT_BASE dht: The dht instance to use to send the message
            :param bytes info_hash: A 160bits (20 bytes) torrent id to announce
            :param int port: The tcp port where data for ``info_hash`` is available
        """

        cdef char* tk
        cdef char* ih
        if self.id in dht.mytoken and (time.time() - dht.mytoken[self.id][1]) < 600:
            id = dht.myid.value
            info_hash = ID.to_bytes(info_hash)
            token = dht.mytoken[self.id][0]
            msg = BMessage()
            dht._set_transaction_id(msg)
            msg.set_y("q", 1)
            msg.set_q("announce_peer", 13)
            msg.set_a(True)
            msg.set_id(id, len(dht.myid))
            msg.set_info_hash(info_hash, len(info_hash))
            msg.set_port(port)
            msg.set_token(token, len(info_hash))
            self._failed+=1
            dht.sendto(msg.encode(), (self.ip, self.port))

        else:
            raise NoTokenError()

@total_ordering
class Bucket(list):
    """
        A bucket of nodes in the routing table

        :param bytes id: A prefix identifier from 0 to 169 bits for the bucket
        :param int id_length: number of signifiant bit in ``id`` (can also be seen as the length
            between the root and the bucket in the routing table)
        :param iterable init: some values to store initialy in the bucket
    """
    #: maximun number of element in the bucket
    max_size = 8
    #: Unix timestamp, ast time the bucket had been updated
    last_changed = 0
    #: A prefix identifier from 0 to 169 bits for the bucket
    id = None
    #: number of signifiant bit in :attr:`id`
    id_length = 0

    __slot__ = ("id", "id_length")

    def own(self, id):
        """
            :param bytes id: A 60bit (20 Bytes) identifier
            :return: ``True`` if ``id`` is handled by this bucket
            :rtype: bool
        """
        if not self.id:
            return True
        if id.startswith(self.id[:self.id_length//8]):
            i=-1
            try:
                for i in range(self.id_length//8*8, self.id_length):
                    if nbit(self.id, i) !=  nbit(id, i):
                        return False
                return True
            except IndexError as e:
                print("%r i:%s selfid:%s:%s:%r nodeid:%d:%r %r" % (e, i, len(self.id), self.id_length, self.id, len(id), id, self))
                return False
        else:
            return False

    def __init__(self, id=b"", id_length=0, init=None):
        self.id = id
        self.id_length = id_length # en bit
        if init:
            super(Bucket, self).__init__(init)

    def random_id(self):
        """
            :return: A random id handle by the bucket
            :rtype: bytes

            This is used to send find_nodes for randoms ids in a bucket
        """
        id = ID()
        id_length = self.id_length
        id_end = bytes(bytearray((id[id_length//8],)))
        tmp = ''
        if id_length>0:
            try:
               id_start = bytes(bytearray((self.id[id_length//8],)))
            except IndexError:
                id_start = b"\0"
            for i in range((id_length % 8)):
                tmp += '1' if nbit(id_start, i) == 1 else '0'
        for i in range((id_length % 8), 8):
            tmp += '1' if nbit(id_end, i) == 1 else '0'
        try:
            char = bytes(bytearray((int(tmp, 2),)))
        except ValueError:
            print(tmp)
            raise
        return ID(self.id[0:id_length//8] + char + id[id_length//8+1:])

    def get_node(self, id):
        """
            :return: A :class:`Node` with :attr:`Node.id`` equal to ``id``
            :rtype: Node
            :raises: :class:`NotFound` if no node is found within this bucket
        """
        for n in self:
            if n.id == id:
                return n
        raise NotFound()

    def add(self, dht, node):
        """
            Try to add a node to the bucket.

            :param DHT_BASE dht: The dht instance the node to add is from
            :param Node node: A node to add to the bucket
            :raises: :class:`BucketFull` if the bucket is full

            Notes:
                The addition of a node to a bucket is done as follow:
                    * if the bucket is not full, just add the node
                    * if the bucket is full
                        * if there is some bad nodes in the bucket, remove a bad node and add the
                          node
                        * if there is some questionnable nodes (neither good not bad), send a ping
                          request to the oldest one, discard the node
                        * if all nodes are good in the bucket, discard the node
        """
        if not self.own(node.id):
            raise ValueError("Wrong Bucket")
        elif node in self:
            try:
                old_node = self.get_node(node.id)
                old_node.ip = node.ip
                old_node.port = node.port
                self.last_changed = time.time()
            except NotFound:
                try:
                    self.remove(node)
                except: pass
        elif len(self) < self.max_size:
            self.append(node)
            self.last_changed = time.time()
        else:
            for n in self:
                if n.bad:
                    try:
                        self.remove(n)
                    except ValueError:
                        pass
                    self.add(dht, node)
                    return
            l=list(self)
            l.sort()
            if not l[-1].good:
                l[-1].ping(dht)
            raise BucketFull()

    def split(self, rt, dht):
        """
            Split the bucket into two buckets

            :param RoutingTable rt: The routing table handling the bucket
            :param DHT_BASE dht: A dht using ``rt`` as routing table
            :return: A couple of two bucket, the first one this the last significant bit of its id
                equal to 0, the second, equal to 1
            :rtype: tuple
        """
        if len(self) < self.max_size:
            raise BucketNotFull("Bucket not Full %r" % self)
        if self.id_length < 8*len(self.id):
            new_id = self.id
        else:
            new_id = self.id + b"\0"
        b1 = Bucket(id=new_id, id_length=self.id_length + 1)
        b2 = Bucket(id=nflip(new_id, self.id_length), id_length=self.id_length + 1)
        for node in self:
            try:
                if b1.own(node.id):
                    b1.add(dht, node)
                elif b2.own(node.id):
                    b2.add(dht, node)
                else:
                    print("%r" % self)
                    raise ValueError("%r %r not in bucket" % (node, node.id))
            except BucketFull:
                rt.add(dht, node)
        if nbit(b1.id, self.id_length) == 0:
            return (b1, b2)
        else:
            return (b2, b1)

    def merge(self, bucket):
        """
            Merge the bucket with ``bucket``

            :param Bucket bucket: a bucket to be merged with
            :return: The merged bucket
            :rtype: Bucket
        """
        l = [n for l in zip(self, bucket) for n in l if n.good][:self.max_size]
        return Bucket(id=self.id, id_length=self.id_length - 1, init=l)

    @property
    def to_refresh(self):
        return time.time() - self.last_changed > 15 * 60


    def __hash__(self):
        return hash(utils.id_to_longid(ID.to_bytes(self.id))[:self.id_length])

    def __eq__(self, other):
        try:
            return self.id_length == other.id_length and self.id == other.id
        except AttributeError as e:
            print ("%r" % e)
            return False

    def __lt__(self, other):
        try:
            if self.id_length == other.id_length:
                return self.id < other.id
            else:
                return self.id_length < other.id_length
        except AttributeError:
            raise ValueError("%s not comparable with %s" % (other.__class__.__name__, self.__class__.__name__))


DHT = type("DHT", (DHT_BASE,), {'__doc__': DHT_BASE.__doc__})


class NotFound(Exception):
    pass

class RoutingTable(object):
    """
        A routing table for one or more :class:`DHT_BASE` instances

        :param utils.Scheduler scheduler: A scheduler instance
        :param int debuglvl: Level of verbosity, default to ``0``.
    """
    #: :class:`int` the routing table instance verbosity level
    debuglvl = 0
    #: the routing table storage data structure, an instance of :class:`datrie.Trie`
    trie = None
    #: the state (stoped ?) of the routing table
    stoped = True
    #: Is a merge sheduled ?
    need_merge = False
    #: :class:`list` of the :class:`Thread<threading.Thread>` of the routing table instance
    threads = []
    #: A class:`list` of couple (weightless thread name, weightless thread function)
    to_schedule = []
    #: prefix in logs and threads name
    prefix = ""
    #: current height of the tree :attr:`trie` structure of the routing table
    _heigth = 1
    #: A set of registered dht instance with this routing table
    _dhts = set()
    #: A set of torrent id
    _info_hash = set()
    #: a set of dht id
    _split_ids = set()
    #: internal list of supposed alive threads
    _threads = []
    #: a set of bucket id to merge (keys of :class:`datrie.Trie`)
    _to_merge = set()
    #: internal list of supposed zombie (asked to stop but still running) threads
    _threads_zombie= []
    #: last debug message, use to prevent duplicate messages over 5 seconds
    _last_debug = ""
    #: time of the lat debug message, use to prevent duplicate messages over 5 seconds
    _last_debug_time = 0
    #: a :class:`utils.Scheduler` instance
    _scheduler = None
    #: A :class:`threading.Lock` instance to prevent concurrent start to happend
    _lock = None

    def __init__(self, scheduler, debuglvl=0, prefix=""):
        self.debuglvl = debuglvl
        self.trie = datrie.Trie(u"01")
        self.trie[u""]=Bucket()
        self._heigth=1
        self._split_ids = set()
        self._info_hash = set()
        self._lock = Lock()
        self._dhts = set()
        self.stoped = True
        self.need_merge = False
        self._threads = []
        self.threads = []
        self._to_merge = set()
        self._threads_zombie= []
        self._last_debug = ""
        self._last_debug_time = 0
        self._scheduler = scheduler
        self.prefix = prefix
        self.to_schedule = [
            ("RT%s:merge_loop" % prefix, self._merge_loop),
            ("RT%s:routine" % prefix, self._routine),
        ]

    def stop_bg(self):
        """stop the routing table and return immediately"""
        if not self.stoped:
            Thread(target=self.stop).start()

    def stop(self):
        """stop the routing table and wait for all threads to terminate"""
        if self.stoped:
            self.debug(0, "Already stoped or stoping in progress")
            return
        for s in self.to_schedule:
            self._scheduler.del_thread(s[0])
        self.stoped = True
        self._threads = [t for t in self._threads[:] if t.is_alive()]
        #self.debug(0, "Trying to terminate thread for 1 minutes")
        for i in range(0, 30):
            if self._threads:
                if i > 5:
                    self.debug(0, "Waiting for %s threads to terminate" % len(self._threads))
                time.sleep(1)
                self._threads = [t for t in self._threads[:] if t.is_alive()]
            else:
                break
        if self._threads:
            self.debug(0, "Unable to stop %s threads, giving up:\n%r" % (len(self._threads), self._threads))
            self.zombie = True
            self._threads_zombie.extend(self._threads)
            self._threads = []

    @property
    def zombie(self):
        return self.stoped and [t for t in self._threads if t.is_alive()]

    def start(self, **kwargs):
        """start the routing table"""
        with self._lock:
            if not self.stoped:
                self.debug(0, "Already started")
                return
            if self.zombie:
                self.debug(0, "Zombie threads, unable de start")
                return self._threads_zombie
            self.stoped = False

        for (name, function) in self.to_schedule:
            self._scheduler.add_thread(name, function)

    def is_alive(self):
        """
            Test if all routing table threads are alive. If a thread is found dead, stop the
            routingtable

            :return: ``True`` if all routing table threads are alive, ``False`` otherwise
            :rtype: bool
        """
        weigthless_threads_satus = [
            self._scheduler.thread_alive(s[0]) for s in self.to_schedule
        ]
        if (
            self.threads is not None and
            all([t.is_alive() for t in self.threads]) and
            all(weigthless_threads_satus)
        ):
            return True
        elif not self._threads and self.stoped and not any(weigthless_threads_satus):
            return False
        else:
            self.debug(0, "One thread died, stopping dht")
            self.stop_bg()
            return True

    def register_torrent(self, id):
        """
            Register a torrent ``id`` (info_hash) for being tracked by the routing table.
            This means that if a node need to be added to the bucket handling ``id``and the
            bucket is full, then, this bucket will be split into 2 buckets

            :param bytes id: A 160 bits (20 Bytes) torrent identifier

            Note:
              torrent ids can automaticaly be release by a dht instance after a get_peers.
              For keeping a torrent registered, use the method :meth:`register_torrent_longterm`
        """
        self._info_hash.add(id)

    def release_torrent(self, id):
        """
            Release a torrent ``id`` (info_hash) and program the routing table to be merged

            :param bytes id: A 160 bits (20 Bytes) torrent identifier
        """
        try:
            self._info_hash.remove(id)
            if not id in self._split_ids:
                try:
                    key = self.trie.longest_prefix(utils.id_to_longid(ID.to_bytes(id)))
                    #self._to_merge.add(key)
                except KeyError:
                    pass
                if not self.need_merge:
                    self.debug(1, "Programming merge")
                    self.need_merge = True
        except KeyError:
            pass

    def _merge_loop(self):
        """Weigthless thread handling the merge of the routing table"""
        yield 0
        next_merge = 0
        # at most one full merge every 10 minutes
        next_full_merge = time.time() + 10 * 60
        while True:
            if self.stoped:
                return
            yield max(next_merge, time.time() + 1)
            if self._to_merge:
                stack = []
                while self._to_merge:
                    stack.append(self._to_merge.pop())
                next_merge = time.time() + 60
                self.debug(1, "Merging %s buckets" % (len(stack),))
                # execute merge partially and return regulary hand to the scheduler
                for i in self._merge(stack):
                    yield i

            if self.need_merge and time.time() > next_full_merge:
                self.need_merge = False
                next_merge = time.time() + 60
                next_full_merge = time.time() + 10 * 60
                # execute merge partially and return regulary hand to the scheduler
                for i in self._merge():
                    yield i

    def register_torrent_longterm(self, id):
        """
            Same as :meth:`register_torrent` but garanty that the torrent wont be released
            automaticaly by the dht.

            :param bytes id: A 160 bits (20 Bytes) torrent identifier
        """
        self._split_ids.add(id)

    def release_torrent_longterm(self, id):
        """
            For releasing torrent registered with the :meth`register_torrent_longterm` method

            :param bytes id: A 160 bits (20 Bytes) torrent identifier

        """
        try:
            self._split_ids.remove(id)
            if not self.need_merge:
                self.debug(1, "Programming merge")
                self.need_merge = True
        except KeyError:
            pass

    def register_dht(self, dht):
        """
            Register a ``dht`` instance to the routing table

            :param DHT_BASE dht: A dht instance

            Notes:
                on start, all dht instances automaticaly register themself to their routing tables
        """
        self._dhts.add(dht)
        self._split_ids.add(dht.myid.value)

    def release_dht(self, dht):
        """
            Release a ``dht`` instance to the routing table, and shedule the routing table for a
            merge.

            Notes:
                on stop, dht automatially release itself from the routing table
        """
        try:
            self._dhts.remove(dht)
        except KeyError:
            pass
        try:
            self._split_ids.remove(dht.myid)
            if not self.need_merge:
                self.debug(1, "Programming merge")
                self.need_merge = True
        except KeyError:
            pass
        if not self._dhts:
            self.stop()

    def debug(self, lvl, msg):
        """same as debug on DHT_BASE"""
        if (
            lvl <= self.debuglvl and
            (msg != self._last_debug or (time.time() - self._last_debug_time) > 5)
        ):
            print("RT%s:%s" % (self.prefix, msg))
            self._last_debug = msg
            self._last_debug_time = time.time()

    def _routine(self):
        """
            Weigthless thread perfoming routine on the routing table like performing quering to
            bucket with no activity and pinging questionnable (neither good nor bad) nodes.
        """
        yield 0
        last_explore_tree = time.time()
        while True:
            #self.clean()
            # exploring the routing table
            if self.stoped:
                return
            yield (last_explore_tree + 60)
            if self._dhts:
                dhts = list(self._dhts)
                dhts_last_elt = len(dhts) - 1
                shuffle(dhts)
                now = time.time()
                i = 0
                for key, bucket in self.trie.items():
                    if self.stoped:
                        return
                    # if trie modifies while looping
                    if not key in self.trie:
                        continue
                    # If bucket inactif for more than 15min, find_node on a random id in it
                    if now - bucket.last_changed > 15 * 60:
                        id = bucket.random_id()
                        nodes = self.get_closest_nodes(id)
                        if nodes:
                            nodes[0].find_node(dhts[randint(0, dhts_last_elt)], id)
                            i += 1
                        del nodes
                    # If questionnable nodes, ping one of them
                    questionable = [node for node in bucket if not node.good and not node.bad]

                    for dht in dhts:
                        if not questionable:
                            break
                        questionable.pop().ping(dht)
                        i+=1
                    del questionable

                    # give back the main in case of very big routing table to the scheduler
                    if i > 1000:
                        yield 0

            last_explore_tree = time.time()

    def empty(self):
        """Empty the routing table, deleting all buckets"""
        self.trie = datrie.Trie("".join(chr(i) for i in range(256)))
        self.trie[u""]=Bucket()

    def stats(self):
        """
            :return: A triple (number of nodes, number of good nodes, number of bad nodes)
            :rtype: tuple
        """
        nodes = 0
        goods = 0
        bads = 0
        others = 0
        try:
            for b in self.trie.values():
                for n in b:
                    nodes+=1
                    if n.good:
                        goods+=1
                    elif n.bad:
                        bads+=1
                    else:
                        others+=1
        except (TypeError, AttributeError):
            pass
        return (nodes, goods, bads)

    def __iter__(self):
        return iter(self.trie.values())

    def get_node(self, id):
        """
            :param bytes id: A 160 bits (20 Bytes) identifier
            :return: A node with id ``id``
            :rtype: Node
            :raises: :class:`NotFound` if no nodes is found
        """
        b = self.find(id)
        return b.get_node(id)

    def find(self, id, errno=0):
        """
            :param bytes id: A 160 bits (20 Bytes) identifier
            :return: The bucket handling ``id``
            :rtype: Bucket
            :raises KeyError: then a racing condition with merging and/or spliting a bucket is met.
                This should not happen

            Notes:
                Duging a split or merge of bucket it is possible that the bucket handling ``id``
                is not found. :meth:`find` will retry at most 20 times to get the bucket.
                In most case, during those retries, the split and/or merge will end and the bucket
                handling ``id`` will be returned.
        """
        try:
            return self.trie.longest_prefix_value(utils.id_to_longid(ID.to_bytes(id)))
        except KeyError as e:
            if errno > 0:
                print("%r:%r" % (id,e))
            try:
                return self.trie[u""]
            except KeyError:
                if errno < 20:
                    return self.find(id, errno=errno+1)
                else:
                    raise

    def get_closest_nodes(self, id, bad=False, errno=0):
        """
            Return the K closest nodes from ``id`` in the routing table

            :param bytes id: A 160 bits (20 Bytes) identifier
            :param bool bad: Should we return bad nodes ? The default is ``False``

            Notes:
                If less than K (=8) good nodes is found, bad nodes will be included it solve
                the case there the connection where temporary lost and all nodes in the routing
                table marked as bad.
                In normal operation, we should always find K (=8) good nodes in the routing table.
        """
        try:
            id = ID(id)
            nodes = set(n for n in self.find(id) if not n.bad)
            try:
                prefix = self.trie.longest_prefix(utils.id_to_longid(id.value))
            except KeyError:
                prefix = u""
            while len(nodes) < Bucket.max_size and prefix:
                prefix = prefix[:-1]
                for suffix in self.trie.suffixes(prefix):
                    nodes = nodes.union(n for n in self.trie[prefix + suffix] if bad or not n.bad)
            nodes = list(nodes)
            nodes.sort(key=lambda x:id ^ x.id)
            # if found less the k good nodes, retrie including bad nodes
            # it solve the case there connection where temporary lost and
            # all nodes in the routing table marked as bad
            if len(nodes) < Bucket.max_size and not bad:
                return self.get_closest_nodes(id, bad=True, errno=errno)
            return nodes[0:Bucket.max_size]
        except KeyError as e:
            if errno>0:
                self.debug(1, "get_closest_nodes:%r" % e)
            return self.get_closest_nodes(id, bad=bad, errno=errno+1)

    def add(self, dht, node):
        """
            Add a node the the routing table

            :param DHT_BASE dht: The dht instance ``node``is from
            :param Node node: The node to add to the routing table
        """
        if node.ip in dht.ignored_ip:
            return
        if utils.ip_in_nets(node.ip, dht.ignored_net):
            return
        b = self.find(node.id)
        try:
            b.add(dht, node)
        except BucketFull:
            # If bucket is full, try to split
            if b.id_length < 160:
                for id in self._split_ids | self._info_hash:
                    if b.own(id):
                        self.split(dht, b)
                        self.add(dht, node)
                        return
            else:
                print("%r" % b)

    def heigth(self):
        """
            :return: the height of the tree of the routing table
            :rtype: int
        """
        return self._heigth

    def split(self, dht, bucket):
        """
            Split ``bucket`` in two

            :param DHT_BASE dht: A dht instance
            :param Bucket bucket: A bucket from the routing table to split

            Notes:
                the routing table cover the entire 160bits space
        """
        try:
            prefix = utils.id_to_longid(bucket.id)[:bucket.id_length]
            (zero_b, one_b) = self.trie[prefix].split(self, dht)
            (zero_b, one_b) = self.trie[prefix].split(self, dht)
            self.trie[prefix + u"1"] = one_b
            self.trie[prefix + u"0"] = zero_b
            self._heigth = max(self._heigth, len(prefix) + 2)
            del self.trie[prefix]
        except KeyError:
            self.debug(2, "trie changed while splitting")
        except BucketNotFull as e:
            self.debug(1, "%r" % e)

    def merge(self):
        """Request a merge to be perform"""
        self.need_merge = True

    def _merge(self, stack=None):
        """
            Perform a merge of the routing table. If ``stack`` is provided, only a partial merge
            on buckets identified by ``stack`` is perform. Otherwise, a full merge of the
            routing table is done.

            :param list stack: An optional list of keys of :attr:`trie` to merge.
        """
        if stack is None:
            stack = self.trie.keys()
            full_merge = True
        else:
            full_merge = False
        if full_merge:
            nodes_before = self.stats()[0]
            if nodes_before < 1000:
                self.debug(1, "Less than 1000 nodes, no merge")
                return
            started = time.time()
        i = 0
        j = 0
        while stack:
            if self.stoped:
                return
            key = stack.pop()
            if not key:
                continue
            to_merge =  True
            for id in self._split_ids | self._info_hash:
                if utils.id_to_longid(id).startswith(key[:-1]):
                    to_merge = False
                    break
            j += 1
            # give back control to the scheduler every 100,000 keys
            if j >= 100000:
                yield 0
            if to_merge:
                try:
                    if key not in self.trie:
                        self.debug(2, "%s gone away while merging" % key)
                        continue
                    prefix0 = key
                    prefix1 = key[:-1] + six.text_type(int(key[-1]) ^ 1)
                    bucket0 = self.trie[prefix0]
                    if prefix1 in self.trie:
                        bucket1 = self.trie[prefix1]
                        bucket = bucket0.merge(bucket1)
                        self.trie[key[:-1]] = bucket
                        del self.trie[prefix1]
                    else:
                        self.trie[key[:-1]] = Bucket(id=bucket0.id, id_length=len(key[:-1]), init=bucket0)
                    del self.trie[prefix0]
                    stack.append(key[:-1])
                except KeyError:
                    self.debug(0, "trie changed while merging")

                i += 1
                # give back control to the scheduler every 1000 buckets merged
                if i >= 1000:
                    yield 0

        if full_merge:
            self._heigth = max(len(k) for k in self.trie.keys()) + 1
            self.debug(1, "%s nodes merged in %ss" % (nodes_before - self.stats()[0], int(time.time() - started)))

