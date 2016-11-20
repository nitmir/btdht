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
try:
    import Queue
except ImportError:
    import queue as Queue
import heapq
import traceback
import struct
import socket
import select
import collections
import netaddr
import binascii
from functools import total_ordering, reduce
from threading import Thread, Lock
from random import shuffle

import datrie

import utils
from utils import ID, nbit, nflip, nset

from .krcp cimport BMessage
from .krcp import BError, ProtocolError, GenericError, ServerError, MethodUnknownError

cdef class DHT_BASE:
    """
    Attributes:
      root (RoutingTable): the dht instance routing table
      bind_port (int): udp port to which this dht instance is binded
      bind_ip (str): ip addresse to which this dht instance is binded
      myid (str): 160bits long (20 Bytes) id of the node running this
        instance of the dht.
      debuglvl (int): Level of verbosity
      master (bool): A boolean value to disting a particular dht instance
      threads (list of Thread): list of the threads of the dht instance
      zombie (bool): True if dht is stopped but one thread or more remains
        alive
    """
    cdef char _myid[20]

    def __init__(self, routing_table=None, bind_port=None, bind_ip="0.0.0.0",
      id=None, ignored_ip=[], debuglvl=0, prefix="", master=False, process_queue_size=500,
      ignored_net=None
    ):
        """
        Note:
           try to use same `id` and `bind_port` over dht restart to increase
           the probability to remain in other nodes buckets

        Args:
          routing_table (RoutingTable, optional): A routing table possibly
            shared between several dht instance. By default a new one is
            instanciated.
          bind_port (int, optional): udp port to which bind this dht instance
            default is to let the system choose an available port.
          bind_ip (str, optional): default to "0.0.0.0".
          id (str, optional): 160bits long (20 Bytes) id of the node running
            this instance of the dht. Default is to choose a random id
          ignored_ip (list of str, optional): a list of ip to ignore message from
          debuglvl (int, optional): Level of verbosity, default to 0
          master (bool, optional): A boolean value to disting a particular dht
            instance among several other then subclassing. Unused. default to False
          process_queue_size(int, optional): Size of the queue of messages waiting
            to be processed by user function (on_`msg`_(query|response)). see
            the `register_message` method. default to 500.
          ignored_net (list of str, optional): a list of ip network in CIDR notation
            to ignore. By default, the list contains all private ip networks.
        """

        # checking the provided id or picking a random one
        if id is not None:
            if len(id) != 20:
                raise ValueError("id must be 20 char long")
            id = ID.to_bytes(id)
        else:
            id = ID().value
        self.myid = ID(id)

        # initialising the routing table
        self.root = RoutingTable() if routing_table is None else routing_table
        # Map beetween transaction id and messages type (to be able to match responses)
        self.transaction_type={}
        # Token send on get_peers query reception
        self.token=collections.defaultdict(list)
        # Token received on get_peers response reception
        self.mytoken={}
        # Map between torrent hash on list of peers
        self._peers=collections.defaultdict(collections.OrderedDict)
        self._got_peers=collections.defaultdict(collections.OrderedDict)
        self._get_peer_loop_list = []
        self._get_peer_loop_lock = {}
        self._get_closest_loop_lock = {}
        self._to_process = Queue.Queue(maxsize=process_queue_size)
        self._to_process_registered = set()

        self.bind_port = bind_port
        self.bind_ip = bind_ip

        self.sock = None

        if ignored_net is None:
            ignored_net = [
                '10.0.0.0/8', '172.16.0.0/12','198.18.0.0/15',
                '169.254.0.0/16', '192.168.0.0/16', '224.0.0.0/4', '100.64.0.0/10',
                '0.0.0.0/8','127.0.0.0/8','192.0.2.0/24','198.51.100.0/24','203.0.113.0/24',
                '192.0.0.0/29', '240.0.0.0/4', '255.255.255.255/32',
            ]
        self.ignored_ip = ignored_ip
        self.ignored_net = [netaddr.IPNetwork(net) for net in ignored_net]
        self.debuglvl = debuglvl
        self.prefix = prefix

        self._threads=[]
        self.threads = []

        self.master = master
        self.stoped = True
        self._threads_zombie = []
        self._last_debug = ""
        self._last_debug_time = 0


    def save(self, filename=None, max_node=None):
        """save the current list of nodes to `filename`. 

        Args:
          filename (str, optional): filename where the list of known node is saved.
            default to dht_`id`.status
          max_node (int, optional): maximun number of nodes to save. default is all
            the routing table
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
        """load a list of nodes from `filename`.

        Args:
          filename (str, optional): filename where the list of known node is load from.
            default to dht_`id`.status
          max_node (int, optional): maximun number of nodes to save. default is all
            nodes in the file
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
        """Stop the dht"""
        if self.stoped:
            self.debug(0, "Already stoped or soping in progress")
            return
        self.stoped = True
        self.root.release_dht(self)
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
            self._threads_zombie.extend(self._threads)
            self._threads = []
        
        if self.sock:
            try:self.sock.close()
            except: pass
        
    @property
    def zombie(self):
        return bool(self.stoped and [t for t in self._threads if t.is_alive()])

    def start(self):
        """Start the threads of the dht"""
        if not self.stoped:
            self.debug(0, "Already started")
            return
        if self.zombie:
            self.debug(0, "Zombie threads, unable de start")
            return self._threads_zombie
        self.root.register_dht(self)


        if self.root.stoped:
            self.root.start()
        self.root_heigth = 0
        self.stoped = False
        self.root.last_merge = 0
        self.socket_in = 0
        self.socket_out = 0
        self.last_socket_stats = time.time()
        self.last_msg = time.time()
        self.last_msg_rep = time.time()
        self.long_clean = time.time()
        self.init_socket()

        self.threads = []
        for f, name in [(self._recv_loop, 'recv'), (self._send_loop, 'send'), (self._routine, 'routine'),
                          (self._get_peers_closest_loop, 'get_peers_closest'), (self._process_loop, 'process_msg')]:
            t = Thread(target=f)
            t.setName("%s:%s" % (self.prefix, name))
            t.daemon = True
            t.start()
            self._threads.append(t)
            self.threads.append(t)

    def is_alive(self):
        """Test if all threads of the dht are alive, stop the dht if one of the thread is dead

        Returns:
          True if all dht threads are alive, False otherwise and stop all threads
        """
        if self.threads and reduce(lambda x,y: x and y, [t.is_alive() for t in self.threads]):
            return True
        elif not self._threads and self.stoped:
            return False
        else:
            self.debug(0, "One thread died, stopping dht")
            self.stop_bg()
            return False
        

    def debug(self, lvl, msg):
        """to print `msg` if `lvl` > `debuglvl`

        Note:
          duplicate messages are removed

        Args:
          lvl (int): minimal level for `debuglvl` to print `msg`
          msg (str): message to print
        """
        if lvl <= self.debuglvl and (self._last_debug != msg or (time.time() - self._last_debug_time)>5):
            print(self.prefix + msg)
            self._last_debug = msg
            self._last_debug_time = time.time()

    def socket_stats(self):
        """Statistic on send/received messages

        Note:
            The counter are reset to 0 on each call

        Returns:
            The couple (number a received, number of sent) messages
        """
        now = time.time()
        in_s = self.socket_in
        self.socket_in = 0
        out_s = self.socket_out
        self.socket_out = 0
        delta = now - self.last_socket_stats
        self.last_socket_stats = now
        return (in_s, out_s, delta)

    def init_socket(self):
        """Initialize the UDP socket of the DHT"""
        self.debug(0, "init socket for %s" % binascii.b2a_hex(self.myid.value))
        if self.sock:
             try:self.sock.close()
             except: pass
        self._to_send = Queue.Queue()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, IN.IP_MTU_DISCOVER, IN.IP_PMTUDISC_DO)
        self.sock.setblocking(0)
        if self.bind_port:
            self.sock.bind((self.bind_ip, self.bind_port))
        else:
            self.sock.bind((self.bind_ip, 0))
            self.bind_port = self.sock.getsockname()[1]


    def sleep(self, t, fstop=None):
        """Sleep for t seconds. If the dht is requested to be stop, run `fstop` and exit

        Note:
            Dont use it in the main thread otherwise it can exit before child threads

        Args:
          fstop (callable, optional): A callable object taking no argument called on dht stop
             during the sleep
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
        """Announce `info_hash` available on `port` to the K closest nodes from
           `info_hash` found in the dht

        Args:
          info_hash (str): A 160bits (20 Bytes) long identifier to announce
          port (int): tcp port on which `info_hash` if avaible on the current node
          delay (int, optional): delay in second to wait before starting to look for
            the K closest nodes into the dht. default ot 0
          block (bool, optional): wait until the announce in done if True, return immediately
            otherwise. default ot True.
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
            heapq.heappush(self._get_peer_loop_list, (ts, info_hash, tried_nodes, closest, typ, callback, None))
            if block:
                while info_hash in self._get_closest_loop_lock and not self.stoped:
                    self.sleep(0.1)

    def _add_peer(self, info_hash, ip, port):
        """Store a peer after a  announce_peer query"""
        if ip not in self.ignored_ip and not utils.ip_in_nets(ip, self.ignored_net):
            self._peers[info_hash][(ip,port)]=time.time()
            # we only keep at most 100 peers per hash
            if len(self._peers[info_hash]) > 100:
                self._peers[info_hash].popitem(False)

    def _add_peer_queried(self, info_hash, ip, port):
        """Store a peer after a  announce_peer query"""
        if ip not in self.ignored_ip and not utils.ip_in_nets(ip, self.ignored_net):
            self._got_peers[info_hash][(ip,port)]=time.time()
            # we only keep at most 1000 peers per hash
            if len(self._got_peers[info_hash]) > 1000:
                self._got_peers[info_hash].popitem(False)

    def get_peers(self, hash, delay=0, block=True, callback=None, limit=10):
        """Return a list of at most 1000 (ip, port) downloading `hash` or pass-it to `callback`

        Note:
          if `block` is False, the returned list will be most likely empty on the first call

        Args:
          hash (str): A 160bits (20 Bytes) long identifier to look for peers
          delay (int, optional): delay in second to wait before starting to look for
            the K closest nodes into the dht. default ot 0
          block (bool, optional): wait until the announce in done if True, return immediately
            otherwise. default ot True.
          callback (callable, optional): A callable accepting a argument of type list of (str, int)
            called then peers have been found.
          limit (int, optional): max number of peer to look for before returning. default to 10.

        Returns:
            a list of (str, int) peers downloading `hash`
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
        """Function run by the thread exploring the DHT"""
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
            self.sleep(tosleep, stop)

    def _get_peers(self, info_hash, compact=True, errno=0):
        """Return peers store locally by remote announce_peer"""
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
        """return the current K closest nodes from `id`

        Note:
          Contact information for peers is encoded as a 6-byte string.
          Also known as "Compact IP-address/port info" the 4-byte IP address
          is in network byte order with the 2 byte port in network byte order
          concatenated onto the end.
          Contact information for nodes is encoded as a 26-byte string.
          Also known as "Compact node info" the 20-byte Node ID in network byte
          order has the compact IP-address/port info concatenated to the end.

        Args:
          id (str): A 160bits (20 Bytes) long identifier to look for closest nodes
            in the routing table
          compact (bool, optional): default to False

        Returns:
          A list of Compact node info if `compact` is True, a list of
          `Node` instances otherwise.
        """
        l = list(self.root.get_closest_nodes(id))
        if compact:
            return b"".join(n.compact_info() for n in l)
        else:
            return list(self.root.get_closest_nodes(id))
    
    def bootstarp(self):
        """boostrap the DHT to some wellknown nodes"""
        self.debug(0,"Bootstraping")
        for addr in [("router.utorrent.com", 6881), ("genua.fr", 6880), ("dht.transmissionbt.com", 6881)]:
            msg = BMessage()
            msg.y = b'q'
            msg.q = b"find_node"
            self._set_transaction_id(msg)
            msg.set_a(True)
            msg[b"id"] = self.myid.value
            msg[b"target"] = self.myid.value
            self.sendto(msg.encode(), addr)



    def _update_node(self, obj):
        """update a node the in routing table on msg received"""
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

    def _send_loop(self):
        """function lauch by the thread sending the udp msg"""
        while True:
            if self.stoped:
                return
            try:
                (msg, addr) = self._to_send.get(timeout=1)
                while True:
                    if self.stoped:
                        return
                    try:
                        (_,sockets,_) = select.select([], [self.sock], [], 1)
                        if sockets:
                            self.sock.sendto(msg, addr)
                            self.socket_out+=1
                            break
                    except socket.error as e:
                        if e.errno in [90, 13]: # Message too long
                            self.debug(0, "send:%r %r %r" % (e, addr, msg))
                            break
                        if e.errno not in [11, 1]: # 11: Resource temporarily unavailable
                            self.debug(0, "send:%r %r" % (e, addr) )
                            raise
            except Queue.Empty:
                pass

    def sendto(self, msg, addr):
        """program a msg to be send over the network

        Args:
           msg (str): message to be send to
           addr (tuple of str, port): address to send to
        """
        self._to_send.put((msg, addr))

    def _recv_loop(self):
        """function lauch by the thread receiving the udp messages from the DHT"""
        while True:
            if self.stoped:
                return
            try:
                (sockets,_,_) = select.select([self.sock], [], [], 1)
            except socket.error as e:
                self.debug(0, "recv:%r" %e )
                raise

            if sockets:
                try:
                    data, addr = self.sock.recvfrom(4048)
                    if addr[0] in self.ignored_ip:
                        continue
                    if utils.ip_in_nets(addr[0], self.ignored_net):
                        continue
                    if addr[1] < 1 or addr[1] > 65535:
                        self.debug(1, "Port should be whithin 1 and 65535, not %s" % addr[1])
                        continue
                    if len(data) < 20:
                        continue
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

                        self.socket_in+=1
                        self.last_msg = time.time()

                        # send it
                        self.sendto(reponse.encode(), addr)
                    # on response
                    elif obj.y == b"r":
                        # process the response
                        self._process_response(obj, obj_opt)

                        self.socket_in+=1
                        self.last_msg = time.time()
                        self.last_msg_rep = time.time()
                    # on error
                    elif obj.y == b"e":
                        # process it
                        self.on_error(obj, obj_opt)

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

                
    cdef void _set_transaction_id(self, BMessage query, int id_len=6):
        """Set the transaction id (key t of the dictionnary) on a query"""
        id = os.urandom(id_len)
        if id in self.transaction_type:
            self._set_transaction_id(query, id_len=id_len+1)
        self.transaction_type[id] = (None, time.time(), query)
        query.set_t(id, id_len)

    def _get_token(self, ip):
        """Generate a token for `ip`"""
        if ip in self.token and self.token[ip][-1][1] < 300:
            #self.token[ip] = (self.token[ip][0], time.time())
            return self.token[ip][-1][0]
        else:
            id = os.urandom(4)
            self.token[ip].append((id, time.time()))
            return id

    def _get_valid_token(self, ip):
        """Return a list of valid tokens for `ip`"""
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
        """Function cleaning datastructures of the DHT"""
        now = time.time()

        to_delete = []
        for id in self.transaction_type:
            if now - self.transaction_type[id][1] > 30:
                to_delete.append(id)
        for key in to_delete:
            del self.transaction_type[key]

        self._threads = [t for t in self._threads[:] if t.is_alive()]

        if now - self.last_msg > 2 * 60:
            self.debug(0, "No msg since more then 2 minutes")
            self.stop()
        elif now - self.last_msg_rep > 5 * 60:
            self.debug(0, "No msg response since more then 5 minutes")
            self.stop()

        self.clean()

        # Long cleaning
        if now - self.long_clean >= 15 * 60:
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
                del self.mytoken[id]

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
                    del self._peers[hash][peer]
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
                    del self._got_peers[hash][peer]
                if not self._got_peers[hash]:
                    del self._got_peers[hash]

            self.clean_long()

            self.long_clean = now

    def build_table(self):
        """Build the routing table by querying find_nodes on his own id"""
        nodes = self.get_closest_nodes(self.myid)
        for node in nodes:
            node.find_node(self, self.myid)
        return bool(nodes)

    def _routine(self):
        """function lauch by the thread performing some routine (boostraping, building the routing table, cleaning) on the DHT"""
        next_routine = time.time() + 15
        while True:
            if self.stoped:
                return
            self.sleep(next_routine - time.time())
            now = time.time()
            next_routine = now + 15

            # calling clean every 15s
            self._clean()

            # Searching its own id while the Routing table is growing
            if self.root_heigth != self.root.heigth():
                self.debug(1, "Fetching my own id")
                if self.build_table():
                    self.root_heigth += 1

            # displaying some stats
            (in_s, out_s, delta) = self.socket_stats()
            if in_s <= 0 or self.debuglvl > 0:
                (nodes, goods, bads) = self.root.stats()
                if goods <= 0:
                    self.bootstarp()
                self.debug(0 if in_s <= 0 and out_s > 0 and goods < 20 else 1, "%d nodes, %d goods, %d bads | in: %s, out: %s en %ss" % (nodes, goods, bads, in_s, out_s, int(delta)))


    def register_message(self, msg):
        """register a dht message to be processed

        Note:
          on query receival, the function on_`msg`_query will be call with the
            query as parameter
          on response receival, the function on_`msg`_response will be called with
            the query and the response as parameters

        Args:
          msg (str): a dht message type like ping, find_node, get_peers or announce_peer
        """
        self._to_process_registered.add(msg)

    def on_error(self, error, query=None):
        """function called then a query has be responded by an error message. Can safely the overloaded

        Args:
          error (BError): An error instance
          query (BMessage, optional): query that was reply by an error
        """
        pass
    def on_ping_response(self, query, response):
        """function called on a ping response reception. Can safely the overloaded

        Args:
          query (BMessage): the sent query object
          response (BMessage): the received response object
        """
        pass
    def on_find_node_response(self, query, response):
        """function called on a find_node response reception. Can safely the overloaded

        Args:
          query (BMessage): the sent query object
          response (BMessage): the received response object
        """
        pass
    def on_get_peers_response(self, query, response):
        """function called on a get_peers response reception. Can safely the overloaded

        Args:
          query (BMessage): the sent query object
          response (BMessage): the received response object
        """
        pass
    def on_announce_peer_response(self, query, response):
        """function called on a announce_peer response reception. Can safely the overloaded

        Args:
          query (BMessage): the sent query object
          response (BMessage): the received response object
        """
        pass
    def on_ping_query(self, query):
        """function called on a ping query reception. Can safely the overloaded

        Args:
          query (BMessage): the received query object
        """
        pass
    def on_find_node_query(self, query):
        """function called on a find_node query reception. Can safely the overloaded

        Args:
          query (BMessage): the received query object
        """
        pass
    def on_get_peers_query(self, query):
        """function called on a get_peers query reception. Can safely the overloaded

        Args:
          query (BMessage): the received query object
        """
        pass
    def on_announce_peer_query(self, query):
        """function called on a announce query reception. Can safely the overloaded

        Args:
          query (BMessage): the received query object
        """
        pass
    def _on_ping_response(self, query, response):
        pass
    def _on_find_node_response(self, query, response):
        nodes = Node.from_compact_infos(response.get(b"nodes", b""))
        for node in nodes:
            try:
                self.root.add(self, node)
            except AttributeError:
                print("AttributeError: %r in _on_find_node_response" % node)
                raise
        self.debug(2, "%s nodes added to routing table" % len(nodes))
    def _on_get_peers_response(self, query, response):
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
        pass

    def _on_ping_query(self, query):
        pass
    def _on_find_node_query(self, query):
        pass
    def _on_get_peers_query(self, query):
        pass
    def _on_announce_peer_query(self, query):
        try:
            if query.get(b"implied_port", 0) != 0:
                if query.addr[1] > 0 and query.addr[1] < 65536:
                    self._add_peer(info_hash=query[b"info_hash"], ip=query.addr[0], port=query.addr[1])
                else:
                    self.debug(1, "Invalid port number on announce %s, sould be within 1 and 65535" % query.addr[1])
            else:
                if query[b"port"] > 0 and query[b"port"] < 65536:
                    self._add_peer(info_hash=query[b"info_hash"], ip=query.addr[0], port=query[b"port"])
                else:
                    self.debug(1, "Invalid port number on announce %s, sould be within 1 and 65535" % query["port"])
        except KeyError as e:
            raise ProtocolError(query.t, b"Message malformed: %s key is missing" % e.message)    


    def _process_response(self, obj, query):
        if query.q in [b"find_node", b"ping", b"get_peers", b"announce_peer"]:
            getattr(self, '_on_%s_response' % query.q.decode())(query, obj)
        if query.q in self._to_process_registered:
            try:
                self._to_process.put_nowait((query, obj))
            except Queue.Full:
                self.debug(0, "Unable to queue msg to be processed, QueueFull")
            #getattr(self, 'on_%s_response' % query.q)(query, obj)

    def _process_query(self, obj):
        if obj.q in [b"find_node", b"ping", b"get_peers", b"announce_peer"]:
            getattr(self, '_on_%s_query' % obj.q.decode())(obj)
        if obj.q in self._to_process_registered:
            try:
                self._to_process.put_nowait((obj, None))
            except Queue.Full:
                self.debug(0, "Unable to queue msg to be processed, QueueFull")
            #getattr(self, 'on_%s_query' % obj.q)(obj)

    def _process_loop(self):
        """function lauch by the thread processing messages"""
        while True:
            if self.stoped:
                return
            try:
                (query, response) = self._to_process.get(timeout=1)
                if response is None:
                    getattr(self, 'on_%s_query' % query.q.decode())(query)
                else:
                    getattr(self, 'on_%s_response' % query.q.decode())(query, response)
            except Queue.Empty:
                pass

    def _decode(self, s, addr):
        """decode a message"""
        try:
            msg = BMessage(addr=addr, debug=self.debuglvl)
            msg.decode(s, len(s))
        except ValueError as e:
            if self.debuglvl > 0:
                traceback.print_exc()
                self.debug(1, "%s for %r" % (e, addr))
            raise ProtocolError(b"")
        try:
            if msg.y == b"q":
                return msg, None
            elif msg.y == b"r":
                if msg.t in self.transaction_type:
                    ttype = self.transaction_type[msg.t][0]
                    query = self.transaction_type[msg.t][2]
                    return msg, query
                else:
                    raise GenericError(msg.t, b"transaction id unknown")
            elif msg.y == b"e":
                query = self.transaction_type.get(msg.t, (None, None, None))[2]
                if msg.errno == 201:
                    self.debug(2, "ERROR:201:%s pour %r" % (msg.errmsg, self.transaction_type.get(msg.t, {})))
                    return GenericError(msg.t, msg.errmsg), query
                elif msg.errno == 202:
                    self.debug(2, "ERROR:202:%s pour %r" % (msg.errmsg, self.transaction_type.get(msg.t, {})[2].encode()))
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
                self.debug(0, "UNKNOWN MSG: %s" % msg)
                raise ProtocolError(msg.t)
        except KeyError as e:
            raise ProtocolError(msg.t, b"Message malformed: %s key is missing" % e.message)
        except IndexError:
            raise ProtocolError(msg.t, b"Message malformed")


class BucketFull(Exception):
    pass

class BucketNotFull(Exception):
    pass

class NoTokenError(Exception):
    pass

cdef class Node:
    """A node of the dht in the routing table

    Note:
      A good node is a node has responded to one of our queries within the last
      15 minutes. A node is also good if it has ever responded to one of our
      queries and has sent us a query within the last 15 minutes. After 15 minutes
      of inactivity, a node becomes questionable. Nodes become bad when they fail
      to respond to multiple queries in a row.

    Attributes:
      id (str): 160bits (20 Bytes) identifier of the node
      ip (str): ip address of the node in doted notation
      port (int): port of the node
      good (bool): True if the node is good
      bad (bool): True if the node is bad
      last_response (bool): last response date in secondes since epoch
      last_query (bool): last query date in secondes since epoch
      failed (int): number of reponse pending (increse on sending query to the
        node, set to 0 on reception from the node)

    """
    cdef char _id[20]
    cdef char _ip[4]
    cdef int _port
    cdef int _last_response
    cdef int _last_query
    cdef int _failed

    def __init__(self, id,ip,int port, int last_response=0,int last_query=0,int failed=0):
        """
        Args:
          id (str): A 160bits (20 Bytes) identifier
          ip (str): ip address of the node in doted notation
          port (int): port of the node
          last_response (int, optional): last response (secondes since epoch)
            from the node to one of our query. default is 0
          last_query (int, optional): last query (secondes since epoch) from
            the node. default is 0
          failed (int, optional): number of pending response from the node. default is 0
        """
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


    def __dealloc__(self):
        with nogil:
            #free(self._id)
            #free(self._ip)
            pass

    property port:
        def __get__(self):return self._port
        def __set__(self, int i):self._port = i
    property last_response:
        def __get__(self):return self._last_response
        def __set__(self, int i):self._last_response = i
    property last_query:
        def __get__(self):return self._last_query
        def __set__(self, int i):self._last_query = i
    property failed:
        def __get__(self):return self._failed
        def __set__(self, int i):self._failed = i
    property id:
        def __get__(self):
            return self._id[:20]
    property good:
        def __get__(self):
            now = time.time()
            # A good node is a node has responded to one of our queries within the last 15 minutes.
            # A node is also good if it has ever responded to one of our queries and has sent us a query within the last 15 minutes.
            return ((now - self.last_response) < 15 * 60) or (self.last_response > 0 and (now - self.last_query) < 15 * 60)

    property bad:
        def __get__(self):
            # Nodes become bad when they fail to respond to multiple queries in a row.
            return not self.good and self.failed > 3

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
        return struct.pack("!20s4sH", self.id, self._ip, self.port)

    @classmethod
    def from_compact_infos(cls, infos, v=""):
        """Instancy nodes from multiple compact node info string

        Note:
          Contact information for peers is encoded as a 6-byte string.
          Also known as "Compact IP-address/port info" the 4-byte IP address
          is in network byte order with the 2 byte port in network byte order
          concatenated onto the end.
          Contact information for nodes is encoded as a 26-byte string.
          Also known as "Compact node info" the 20-byte Node ID in network byte
          order has the compact IP-address/port info concatenated to the end.

        Args:
          infos (str): a string contening multiple compact node info
            so its length should be a multiple of 26

        Returns:
          a list of Node instance
        """
        nodes = []
        length = len(infos)
        if length//26*26 != length:
            raise ProtocolError(b"", b"nodes length should be a multiple of 26")
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
        """Instancy nodes from multiple compact node info string

        Note:
          Contact information for peers is encoded as a 6-byte string.
          Also known as "Compact IP-address/port info" the 4-byte IP address
          is in network byte order with the 2 byte port in network byte order
          concatenated onto the end.
          Contact information for nodes is encoded as a 26-byte string.
          Also known as "Compact node info" the 20-byte Node ID in network byte
          order has the compact IP-address/port info concatenated to the end.

        Args:
          infos (str): a string contening one compact node info
            so its length should be exactly 26

        Returns:
          a Node instance
        """
        if len(info) != 26:
            raise EnvironmentError("compact node info should be 26 chars long")
        (id, ip, port) = struct.unpack("!20s4sH", info)
        ip = socket.inet_ntoa(ip)
        id = ID(id)
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
        """send a ping query to the node

        Args:
          dht (DHT_BASE): a dht instance
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
        """send a find_node query to the node

        Args:
          dht (DHT_BASE): a dht instance
          target (str): the 160bits (20 bytes) target node id
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
        """send a get_peers query to the node

        Args:
          dht (DHT_BASE): a dht instance
          info_hash (str): a 160bits (20 bytes) to get downloading peers
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
        """send a announce_peer query to the node

        Args:
          dht (DHT_BASE): a dht instance
          info_hash (str): a 160bits (20 bytes) hash to announce download
          port (int): port where data for `info_hash` is avaible
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
    """A bucket of nodes in the routing table

    Attributes:
       to_refresh (bool): True if the bucket need to be refresh
       max_size (int): maximun number of element in the bucket
       last_changed (int): last time the bucket had been updated un secodes
         since epoch
    """
    max_size = 8
    last_changed = 0

    __slot__ = ("id", "id_length")

    def own(self, id):
        """Args:
          id (str): a 160bit (20 Bytes) identifier

        Returns:
          True if `id` is handle by this bucket
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
        """
        Args:
          id (str): prefix identifier for the bucket
          id_length (int): number of signifiant bit in `id`
            (can also be seen as the length between the root
            and the bucket in the routing table)
          init (iterable, optional): some values to store
            initialy in the bucket
        """
        self.id = id
        self.id_length = id_length # en bit
        if init:
            super(Bucket, self).__init__(init)

    def random_id(self):
        """return a random id handle by the bucket"""
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
        """return the node with id `id` or raise NotFound"""
        for n in self:
            if n.id == id:
                return n
        raise NotFound()

    def add(self, dht, node):
        """Try to add a node to the bucket

        Args:
          dht (DHT_BASE): a dht instance
          node (Node): a node instance
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
        """Split the bucket into two buckets

        Args:
          rt (RoutingTable): a routing table instance
          dht (DHT_BASE): a dht instance

        Returns:
          a tuple of two buckets
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
        """Merge the bucket with `bucket`

        Args:
          bucket (Bucket): bucket to be merged with

        Returns
          A merged bucket
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

class DHT(DHT_BASE):
    pass
class NotFound(Exception):
    pass

class SplitQueue(Queue.Queue):
    def _init(self, maxsize):
        self.queue = collections.OrderedDict()
    def _put(self, item):
        if not item[0] in self.queue:
            self.queue[item[0]] = item[1:-1] + (set(),)
        self.queue[item[0]][-1].add(item[-1])
    def _get(self):
        (key, value) = self.queue.popitem(False)
        return (key, ) + value

class RoutingTable(object):
    """
    Attributs:
      trie (datrie.Trie): the routing table storage data structure
      threads (list of Thread): threads of the routing table
      zombie (bool): True if dht is stopped but one thread or more remains
        alive
    """
    #__slot__ = ("trie", "_heigth", "split_ids", "info_hash", "last_merge", "lock", "_dhts", "stoped")
    def __init__(self, debuglvl=0):
        """
        Args:
          debuglvl (int, optional): level of verbosity. default is 0
        """
        self.debuglvl = debuglvl
        self.trie = datrie.Trie(u"01")
        self.trie[u""]=Bucket()
        self._heigth=1
        self.split_ids = set()
        self.info_hash = set()
        #self.last_merge = 0
        self.lock = Lock()
        self._to_split = SplitQueue()
        self._dhts = set()
        self.stoped = True
        self.need_merge = False
        self._threads = []
        self.threads = []
        self._to_merge = set()
        self._threads_zombie= []
        self._last_debug = ""
        self._last_debug_time = 0

    def stop_bg(self):
        """stop the routing table and return immediately"""
        if not self.stoped:
            Thread(target=self.stop).start()

    def stop(self):
        """stop the routing table and wait for all threads to terminate"""
        if self.stoped:
            self.debug(0, "Already stoped or soping in progress")
            return
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
        
    def start(self):
        """start the routing table"""
        with self.lock:
            if not self.stoped:
                self.debug(0, "Already started")
                return
            if self.zombie:
                self.debug(0, "Zombie threads, unable de start")
                return self._threads_zombie
            self.stoped = False

        self.threads = []
        for f in [self._merge_loop, self._routine, self._split_loop]:
            t = Thread(target=f)
            t.setName("RT:%s" % f.__func__.__name__)
            t.daemon = True
            t.start()
            self._threads.append(t)
            self.threads.append(t)

    def is_alive(self):
        """return True if all routing table threads are alive. Otherwire return False
        and stop the routing table"""
        if self.threads and reduce(lambda x,y: x and y, [t.is_alive() for t in self.threads]):
            return True
        elif not self._threads and self.stoped:
            return False
        else:
            self.debug(0, "One thread died, stopping dht")
            self.stop_bg()
            return True

    def register_torrent(self, id):
        """register a torrent `id` (info_hash) for spliting bucket containing this `id`

        Note:
          torrent can automaticaly be release by a dht instance after a get_peers.
          For keeping a torrent registered, use the method `register_torrent_longterm`
        """
        self.info_hash.add(id)

    def release_torrent(self, id):
        """release a torrent `id` (info_hash) and program the routing table to be merged"""
        try:
            self.info_hash.remove(id)
            if not id in self.split_ids:
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
        next_merge = 0
        # at most one full merge every 10 minutes
        next_full_merge = time.time() + 10 * 60
        while True:
            self.sleep(max(next_merge - time.time(), 1))
            if self._to_merge:
                stack = []
                while self._to_merge:
                    stack.append(self._to_merge.pop())
                next_merge = time.time() + 60
                self.debug(1, "Merging %s buckets" % (len(stack),))
                self._merge(stack)

            if self.need_merge and time.time() > next_full_merge:
                self.need_merge = False
                next_merge = time.time() + 60
                next_full_merge = time.time() + 10 * 60
                self._merge()

    def register_torrent_longterm(self, id):
        """Same as register_torrent but garanty that the torrent wont
        be released automaticaly by the dht
        """
        self.split_ids.add(id)
    def release_torrent_longterm(self, id):
        """for releasing torrent registered with the `register_torrent_longterm` method"""
        try:
            self.split_ids.remove(id)
            if not self.need_merge:
                self.debug(1, "Programming merge")
                self.need_merge = True
        except KeyError:
            pass

    def register_dht(self, dht):
        """Register a `dht` instance to the routing table

        Note:
          on start, dht automaticaly register itself to its
          routing table
        """
        self._dhts.add(dht)
        self.split_ids.add(dht.myid)

    def release_dht(self, dht):
        """release a `dht` instance to the routing table

        Note:
          on stop, dht automatially release itself from the
          routing table
        """
        try: self._dhts.remove(dht)
        except KeyError:pass
        try: 
            self.split_ids.remove(dht.myid)
            if not self.need_merge:
                self.debug(1, "Programming merge")
                self.need_merge = True
        except KeyError:
            pass
        if not self._dhts:
            self.stop()

    def sleep(self, t, fstop=None):
        """same as sleep on DHT_BASE"""
        if t > 0:
            t_int = int(t)
            t_dec = t - t_int
            for i in range(0, t_int):
                time.sleep(1)
                if self.stoped:
                    if fstop:
                        fstop()
                    sys.exit(0)
            time.sleep(t_dec)

    def debug(self, lvl, msg):
        """same as debug on DHT_BASE"""
        if lvl <= self.debuglvl and (msg != self._last_debug or (time.time() - self._last_debug_time) > 5):
            print("RT:%s" % msg)
            self._last_debug = msg
            self._last_debug_time = time.time()

    def _routine(self):
        last_explore_tree = 0
        while True:
            #self.clean()
            # exploring the routing table
            self.sleep(60 - (time.time() - last_explore_tree))
            dhts = list(self._dhts)
            shuffle(dhts)
            now = time.time()
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
                    if nodes and dhts:
                        nodes[0].find_node(dhts[0], id)
                    del nodes
                # If questionnable nodes, ping one of them
                questionable = [node for node in bucket if not node.good and not node.bad]
                
                for dht in dhts:
                    if not questionable:
                        break
                    questionable.pop().ping(dht)
                del questionable

            last_explore_tree = time.time()

    def _split_loop(self):
        while True:
            if self.stoped:
                return
            try:
                (bucket, dht, callbacks) = self._to_split.get(timeout=1)
                self._split(dht, bucket, callbacks)
            except Queue.Empty:
                pass

    def split(self, dht, bucket, callback=None):
        """request for a bucket identified by `id` to be split

        Notes:
          the routing table cover the entire 160bits space

        Args:
          dht (DHT_BASE): a dht instance
          bucket (Bucket): a bucket in the routing table to split
          callback (tuple): first element must be callable and further element
            arguments to pass to the callable.
        """
        self._to_split.put((bucket, dht, callback))


    def empty(self):
        """Remove all subtree"""
        self.trie = datrie.Trie("".join(chr(i) for i in range(256)))
        self.trie[u""]=Bucket()

    def stats(self):
        """return the number of nodes, good nodes, bad nodes"""
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
        """return the node with id `id` or raise `NotFound`"""
        b = self.find(id)
        return b.get_node(id)

    def find(self, id, errno=0):
        """retourn the bucket containing `id`"""
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
        """return the K closest nodes from `id` in the routing table"""
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
        """Add a node the the routing table

        Args:
          dht (DHT_BASE): a dht instance
          node (Node): a node instance to be added
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
                for id in self.split_ids | self.info_hash:
                    if b.own(id):
                        self.split(dht, b, callback=(self.add, (dht, node)))
                        return
            else:
                print("%r" % b)

    def heigth(self):
        """height of the tree of the routing table"""
        return self._heigth

    def _split(self, dht, bucket, callbacks=None):
        try:
            #try:
            #    prefix = self.trie.longest_prefix(utils.id_to_longid(str(bucket.id)))
            #except KeyError:
            #    if u"" in self.trie:
            #        prefix = u""
            #    else:
            #        return
            #print prefix
            #print utils.id_to_longid(str(bucket.id))[:bucket.id_length]
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
        if callbacks:
            for callback in callbacks:
                callback[0](*callback[1])


    def merge(self):
        """Request a merge to be perform"""
        self.need_merge = True

    def _merge(self, stack=None):
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
        while stack:
            if self.stoped:
                return
            key = stack.pop()
            if not key:
                continue
            to_merge =  True
            for id in self.split_ids | self.info_hash:
                if utils.id_to_longid(id).startswith(key[:-1]):
                    to_merge = False
                    break
            if to_merge:
                #with self.lock:
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

        if full_merge:
            self._heigth = max(len(k) for k in self.trie.keys()) + 1
            self.debug(1, "%s nodes merged in %ss" % (nodes_before - self.stats()[0], int(time.time() - started)))
                


