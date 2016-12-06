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

import os
import sys
import netaddr
import binascii
import six
import socket
import collections
import time
import select
try:
    import Queue
except ImportError:
    import queue as Queue
from functools import total_ordering
from threading import Thread, Lock

from libc.stdlib cimport atoi, malloc, free
from libc.string cimport strlen, strncmp, strcmp, strncpy, strcpy
from cython.parallel import prange

from .krcp cimport _decode_string, _decode_int as _decode_long
from .exceptions import BcodeError, FailToStop

cdef extern from "ctype.h":
    int isdigit(int c)

#: an array mapping and int ([0-256]) to the corresponging byte (like the function :func:`chr`)
cdef char _BYTE_TO_BIT[256][8]
# fill _BYTE_TO_BIT array
def __init():
    for i in range(256):
        s = "{0:08b}".format(i).encode("ascii")
        strncpy(_BYTE_TO_BIT[i], <char *>s, 8)
__init()
del __init

cdef char _longid_to_char(char* id) nogil:
    """
        Transform a 8 long string of 0 and 1 like "10110110" in base 2 to the corresponding char
        in base 256.

        :param str id: A 8 Bytes long string with only 0 and 1 as characters
        :return: A single char where the nth bit correspond to the nth bytes of ``id``
        :rtype: str

        Notes:
            This function can be called without the python GIL
    """
    cdef unsigned char i = 0
    if id[0] == 1:
        i = i | (1 << 7)
    if id[1] == 1:
        i = i | (1 << 6)
    if id[2] == 1:
        i = i | (1 << 5)
    if id[3] == 1:
        i = i | (1 << 4)
    if id[4] == 1:
        i = i | (1 << 3)
    if id[5] == 1:
        i = i | (1 << 2)
    if id[6] == 1:
        i = i | (1 << 1)
    if id[7] == 1:
        i = i | (1 << 0)
    return i

cdef char* _longid_to_id(char* longid, int size=160) nogil except NULL:
    """
        Transform a base 2, 160 Bytes long id like "101...001" to its 20 Bytes base 256 form

        :param str longid: A string, of length multiple of 8 contening only 0 and 1 chars
        :param int size: The length of ``longid``, the default is 160.
        :return: A ``size``/8 corresponding base 256 string
        :rtype: str

        Notes:
            This function can be called without the python GIL
    """
    cdef int i
    cdef char* id
    if size//8*8 != size:
        with gil:
            raise ValueError("size must be a multiple of 8")
    id = <char*>malloc((size // 8) * sizeof(char))
    i=0
    while i < size:
        id[i//8] = _longid_to_char(longid + i)
        i+=8
    return id

cdef char* _id_to_longid(char* id, int size=20) nogil:
    """
        Convert a random string ``id`` of length ``size`` to its base 2 equivalent.
        For example, "\\0\\xFF" is converted to "0000000011111111"

        :param bytes id: A random string
        :param int size: The length of ``id``
        :return: The corresponding base 2 string
        :rtype: bytes

        Notes:
            This function can be called without the python GIL
    """
    global _BYTE_TO_BIT
    cdef char* ret = <char*>malloc((size * 8) * sizeof(char))
    cdef int i = 0
    while i < size:
        strncpy(ret + (i*8), _BYTE_TO_BIT[<unsigned char>id[i]], 8)
        i+=1
    return ret

def id_to_longid(char* id, int l=20):
    """
        convert a random bytes to a unicode string of 1 and 0

        For instance: ``"\\0"`` -> ``"00000000"``

        :param bytes id: A random string
        :param int size: The length of ``id``
        :return: The corresponding base 2 unicode string
        :rtype: unicode
    """
    #cdef int l = len(id)
    with nogil:
        ret = _id_to_longid(id, l)
    u = (ret[:l*8]).decode('ascii')
    free(ret)
    return u

def nbit(s, n):
    """
        Allow to retrieve the value of the nth bit of ``s``

        :param bytes s: A byte string
        :param int n: A bit number (n must be smaller than 8 times the length of ``s``)
        :return: The value of the nth bit of ``s`` (``0`` or ``1``)
        :rtype: int
    """
    if six.PY3:
        c = s[n//8]
    else:
        c = ord(s[n//8])
    return int(format(c, '08b')[n % 8])


_NFLIP_BITS = [
    0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010, 0b00000001
]
def nflip(s, n):
    """
        Allow to flip the nth bit of ``s``

        :param bytes s: A byte string
        :param int n: A bit number (n must be smaller than 8 times the length of ``s``)
        :return: The same string except for the nth bit was flip
        :rtype: bytes
    """
    global _NFLIP_BIT
    if six.PY2:
        return s[:n//8]  + chr(ord(s[n//8]) ^ _NFLIP_BITS[n % 8]) + s[n//8+1:]
    else:
        return s[:n//8]  + bytes([s[n//8] ^ _NFLIP_BITS[n % 8]]) + s[n//8+1:]


_NSET_BIT1 = [
    0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010, 0b00000001
]
_NSET_BIT0 = [
    0b01111111, 0b10111111, 0b11011111, 0b11101111, 0b11110111, 0b11111011, 0b11111101, 0b11111110
]
def nset(s, n , i):
    """
        Allow to set the value of the nth bit of ``s``

        :param bytes s: A byte string
        :param int n: A bit number (n must be smaller than 8 times the length of ``s``)
        :param int i: A bit value (``0`` or ``1``)
        :return: ``s`` where the nth bit was set to ``i``
        :rtype: bytes
    """
    global _NSET_BIT0, _NSET_BIT1
    if i == 1:
        return s[:n//8]  + chr(ord(s[n//8]) | _NSET_BIT1[n % 8]) + s[n//8+1:]
    elif i == 0:
        return s[:n//8]  + chr(ord(s[n//8]) & _NSET_BIT0[n % 8]) + s[n//8+1:]
    else:
        raise ValueError("i must be 0 or 1")

def enumerate_ids(size, id):
    """
        Enumerate 2 to the power of ``size`` ids from ``id``

        :param int size: A number of bit to flip in id
        :param bytes id: A 160 bit (20 Bytes) long id
        :return: A list of
            ``id`` and 2 to the power of ``size`` (minus one) ids the furthest from each other
        :rtype: list

        For instance: if ``id=("\\0" * 20)`` (~0 * 160), ``enumerate_ids(4, id)`` will
        return a list with
          *  ``'\\x00\\x00\\x00\\x00\\x00...'`` (~00000000...)
          *  ``'\\x80\\x00\\x00\\x00\\x00...'`` (~10000000...)
          *  ``'@\\x00\\x00\\x00\\x00.......'`` (~0100000000...)
          *  ``'\\xc0\\x00\\x00\\x00\\x00...'`` (~11000000...)

        The can be see as the tree::

                 \\x00
                 /  \\
               1/    \\0
               /      \\
             \\xc0    \\x00
            1/ \\0    1/ \\0
            /   \\    /   \\
          \\xc0 \\x80 @   \\x00

        The root is ``id``, at each level n, we set the nth bit to 1 left and 0 right, ``size``
        if the level we return.

        This function may be usefull to lanch multiple DHT instance with ids the most distributed
        on the 160 bit space.
    """
    def aux(lvl, ids):
        if lvl >= 0:
            l = []
            for id in ids:
                l.append(nset(id, lvl, 0))
                l.append(nset(id, lvl, 1))
            return aux(lvl - 1, l)
        else:
            return ids
    return aux(size - 1, [id])


def _copy_doc(f1):
    """
        A decorator coping docstring from another function

        :param f1: An object with a docstring (functions, methods, classes, ...)
        :return: A decorator that copy the docstring of ``f1``
    """
    def wrap(f2):
        f2.__doc__ = f1.__doc__
        return f2
    return wrap

@total_ordering
class ID(object):
    """
        A 160 bit (20 Bytes) string implementing the XOR distance

        :param id: An optional initial value (:class:`bytes` or :class:`ID`). If not specified,
            a random 160 bit value is generated.
    """

    #: :class:`bytes`, Actual value of the :class:`ID`
    value = None

    @classmethod
    def to_bytes(cls, id):
        """
            :param id: A :class:`bytes` or :class:`ID`
            :return: The value of the ``id``
            :rtype: bytes
        """
        try:
            return id.value
        except AttributeError:
            return id

    @staticmethod
    def __generate():
        """
            :return: A 20 Bytes (160 bit) random string (using ``os.urandom``)
        """
        return os.urandom(20)

    def __init__(self, id=None):
        if id is None:
            self.value = self.__generate()
        else:
            self.value = self.to_bytes(id)

    @_copy_doc(b"".startswith)
    def startswith(self, s):
        return self.value.startswith(s)

    @_copy_doc(b"".__getitem__)
    def __getitem__(self, i):
        return self.value[i]

    def __str__(self):
        raise NotImplementedError()

    def __repr__(self):
        return binascii.b2a_hex(self.value).decode()

    @_copy_doc(b"".__eq__)
    def __eq__(self, other):
        if isinstance(other, ID):
            return self.value == other.value
        elif isinstance(other, str):
            return self.value == other
        else:
            return False

    @_copy_doc(b"".__lt__)
    def __lt__(self, other):
        if isinstance(other, ID):
            return self.value < other.value
        elif isinstance(other, str):
            return self.value < other
        else:
            raise TypeError(
                "unsupported operand type(s) for <: 'ID' and '%s'" % type(other).__name__
            )

    @_copy_doc(b"".__len__)
    def __len__(self):
        return len(self.value)


    def __xor__(self, other):
        """
            Perform a XOR bit by bit between the current id and ``other``

            :param other: A :class:`bytes` or :class:`ID`
            :return: The resulted XORed bit by bit string
            :rtype: bytes
        """
        if isinstance(other, ID):
            if six.PY2:
                return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(self.value, other.value))
            else:
                return bytes([a ^ b for a,b in zip(self.value, other.value)])
        elif isinstance(other, bytes):
            if six.PY2:
                return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(self.value, other))
            else:
                return bytes([a ^ b for a,b in zip(self.value, other)])
        else:
            raise TypeError(
                "unsupported operand type(s) for ^: 'ID' and '%s'" % type(other).__name__
            )

    def __rxor__(self, other):
        """
            Permor a XOR bit by bit between the current id and ``other``

            :param other: A :class:`bytes` or :class:`ID`
            :return: The resulted XORed bit by bit string
            :rtype: bytes
        """
        return self.__xor__(other)

    @_copy_doc(b"".__hash__)
    def __hash__(self):
        return hash(self.value)

def bencode(obj):
    """
        bencode an arbitrary object

        :param obj: A combination of dict, list, bytes or int
        :return: Its bencoded representation
        :rtype: bytes

        Notes:
            This method is just a wrapper around :func:`_bencode`
    """
    try:
        return _bencode(obj)
    except:
        print("%r" % obj)
        raise

def _bencode(obj):
    """
        bencode an arbitrary object

        :param obj: A combination of :class:`dict`, :class:`list`, :class:`bytes` or :class:`int`
        :return: Its bencoded representation
        :rtype: bytes
        :raises EnvironmentError: if ``obj`` is not a combination of :class:`dict`, :class:`list`,
            :class:`bytes` or :class:`int`
        """
    if isinstance(obj, int) or isinstance(obj, float):
        return b"i" + str(obj).encode() +  b"e"
    elif isinstance(obj, bytes):
        return str(len(obj)).encode() + b":" + obj
    elif isinstance(obj, ID):
        return str(len(obj)).encode() + b":" + str(obj)
    elif isinstance(obj, list):
        return b"l" + b"".join(_bencode(o) for o in obj) + b"e"
    elif isinstance(obj, dict):
        l = list(obj.items())
        l.sort()
        d = []
        for (k, v) in l:
            d.append(k)
            d.append(v)
        return b"d" + b"".join(_bencode(o) for o in d) + b"e"
    else:
        raise EnvironmentError(
            "Can only encode int, str, list or dict, not %s" % type(obj).__name__
        )

def bdecode(s):
    """
        bdecode an bytes string

        :param s: A bencoded bytes string
        :return: Its bencoded representation
        :rtype: A combination of :class:`dict`, :class:`list`, :class:`bytes` or :class:`int`
        :raises BcodeError: If failing to decode ``s``

        Notes:
            This method is just a wrapper around :func:`_bdecode`
    """
    return _bdecode(s, len(s))[0]


def bdecode_rest(s):
    """
        bdecode an bytes string

        :param s: A bencoded bytes string
        :return: A couple: (bdecoded representation, rest of the string). If only one bencoded
            object is given as argument, then the 'rest of the string' will be empty
        :rtype: :class:`tuple` (
            combination of :class:`dict`, :class:`list`, :class:`bytes` or :class:`int`, bytes)
        :raises BcodeError: If failing to decode ``s``
    """
    return _bdecode(s, len(s))


cdef _decode_int(char* data, int *i, int max):
    """
        decode an arbitrary long integer

        :param bytes data: The data to decode
        :param int i: An index of ``data`` to start decoding from
        :param int max: the length of ``data``
        :return: A decoded integer if ``data[i]`` is ``b'i'``else False
        :rtype: :class:`int` or :class:`bool:class:`
        :raises BcodeError: if reach end of data before ending decoding or if the value to
            decode is not of the forme ``iNNNNe`` with N a digit
    """
    cdef int j
    #cdef long long ll[1]
    #_decode_long(data, i, max, ll)
    with nogil:
        if data[i[0]] == b'i':
            i[0]+=1
            j = i[0]
            while data[j]!=b'e' and j < max:
                j+=1
            if data[j] == b'e':
                with gil:
                    myint=int(data[i[0]:j])
                    i[0]=j+1
                    if i[0] <= max:
                        return myint
                    else:
                         raise BcodeError(
                            "Reach end of data before end of decoding %s > %s : %r" % (
                                i[0], max, data[:max]
                            )
                        )
            else:
                with gil:
                    raise BcodeError("%s != e at %s %r" % (data[j], j, data[:max]))
        else:
            with gil:
                return False

cdef _decode_list(char* data, int* i, int max):
    """
        decode a list

        :param bytes data: The data to decode
        :param int i: An index of ``data`` to start decoding from
        :param int max: the length of ``data``
        :return: A decoded list of decoded elements
        :rtype: list
        :raises BcodeError: if reach end of data before ending decoding or failing to decode a value
    """
    cdef int j[1]
    i[0]+=1
    l = []
    while data[i[0]] != b'e':
            #if i[0] > 1000000 and (i[0] % 100) == 0:
            #    sys.stdout.write("\r%08d B " % (max -  i[0]))
            if data[i[0]] == b'i':
                l.append(_decode_int(data, i, max))
            elif data[i[0]] == b'l':
                l.append(_decode_list(data, i, max))
            elif data[i[0]] == b'd':
                l.append(_decode_dict(data, i, max))
            elif isdigit(data[i[0]]):
                with nogil:
                    _decode_string(data, i, max, j)
                l.append(data[j[0]:i[0]])
            else:
                raise BcodeError("Unknown type, starting with %r" % data[i[0]])
    i[0]+=1
    return l

cdef _decode_dict(char* data, int* i, int max):
    """
        decode a dict

        :param bytes data: The data to decode
        :param int i: An index of ``data`` to start decoding from
        :param int max: the length of ``data``
        :return: A decoded dict of decoded elements
        :rtype: dict
        :raises BcodeError: if reach end of data before ending decoding or failing to decode a value
            or one of the dict key is not of type bytes
    """
    cdef int j[1]
    i[0]+=1
    d = {}
    while data[i[0]] != b'e':
            #if i[0] > 2000 and (i[0] % 100) == 0:
            #    sys.stdout.write("\r%08d B " % (max - i[0]))
            if isdigit(data[i[0]]):
                with nogil:
                    _decode_string(data, i, max, j)
                key = data[j[0]:i[0]]
            else:
                raise BcodeError("dict key must be string, and thus start with a digit")
            if data[i[0]] == b'e':
                raise BcodeError("dict key without value")
            if data[i[0]] == b'i':
                d[key]=_decode_int(data, i, max)
            elif data[i[0]] == b'l':
                d[key]=_decode_list(data, i, max)
            elif data[i[0]] == b'd':
                d[key]=_decode_dict(data, i, max)
            elif isdigit(data[i[0]]):
                with nogil:
                    _decode_string(data, i, max, j)
                d[key]=data[j[0]:i[0]]
            else:
                raise BcodeError("Unknown type of dict value starting with %r" % data[i[0]])
    i[0]+=1
    return d

cdef _bdecode(char* data, int max):
    """
        bdecode an bytes string

        :param s: A bencoded bytes string
        :return: A couple: (bdecoded representation, rest of the string). If only one bencoded
            object is given as argument, then the 'rest of the string' will be empty
        :rtype: :class:`tuple` (
            combination of :class:`dict`, :class:`list`, :class:`bytes` or :class:`int`, bytes)
        :raises BcodeError: If failing to decode ``s``
    """
    cdef int i[1]
    cdef int j[1]
    i[0]=0
    try:
        if data[i[0]] == b'i':
            ii = _decode_int(data, i, max)
            return ii, data[i[0]:max]
        elif data[i[0]] == b'l':
            l = _decode_list(data, i, max)
            return l, data[i[0]:max]
        elif data[i[0]] == b'd':
            d = _decode_dict(data, i, max)
            return d, data[i[0]:max]
        elif data[i[0]].isdigit():
            with nogil:
                _decode_string(data, i, max, j)
            return data[j[0]:i[0]], data[i[0]:max]
        else:
            raise BcodeError("Unknown type, starting with %r" % data[i[0]])
    except ValueError as e:
        raise BcodeError(str(e))

#cdef _bdecode2(char* s, int* ii):
#    if ii[0] > 2000 and (ii[0] % 100) == 0:

def _bdecode2(s, ii=None):
    if ii is None:
        ii = [0]
    if ii[0] > 2000 and (ii[0] % 100) == 0:
        sys.stdout.write("\r%08d B " % len(s))
    if not s:
        raise BcodeError("Empty bcode")
    if s[0:1] == b"i":
        try:
            i, todo = s.split(b'e', 1)
            ii[0]+=1
            return (int(i[1:]), todo)
        except (ValueError, TypeError):
            # On essaye avec un float même si c'est mal
            try:
                ii[0]+=1
                return (float(i[1:]), todo)
            except:
                raise BcodeError("Not an integer %r" % s)
    elif s[0:1] in [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9']:
        try:
            length, string = s.split(b':', 1)
            length = int(length)
            ii[0]+=1
            return (string[0:length], string[length:])
        except (ValueError, TypeError):
            raise BcodeError("Not a string %r" % s)
    elif s[0:1] == b'l':
        l = []
        try:
            if s[1:2] == b"e":
                ii[0]+=1
                return (l, s[2:])
            item, todo = _bdecode2(s[1:], ii)
            l.append(item)
            while todo[0:1] != b"e":
                item, todo = _bdecode2(todo, ii)
                l.append(item)
            ii[0]+=1
            return (l, todo[1:])
        except (ValueError, TypeError, IndexError):
            raise BcodeError("Not a list %r" % s)
    elif s[0:1] == b'd':
        d = {}
        try:
            if s[1:2] == b"e":
                ii[0]+=1
                return d, s[2:]
            key, todo = _bdecode2(s[1:], ii)
            if todo[0:1] == b"e":
                raise BcodeError("Not bencoded string")
            value, todo = _bdecode2(todo, ii)
            d[key] = value
            while todo[0:1] != b"e":
                key, todo = _bdecode2(todo, ii)
                if todo[0:1] == b"e":
                    raise BcodeError("Not bencoded string")
                #print(todo)
                value, todo = _bdecode2(todo, ii)
                d[key] = value
            if len(todo[1:]) >= len(s):
                raise BcodeError("Endless decoding %r" % todo)
            ii[0]+=1
            return (d, todo[1:])
        except (ValueError, TypeError, IndexError) as e:
            raise BcodeError("Not a dict %r\n%r" % (s, e))
    else:
        raise BcodeError("Not bencoded string %s" % s)


def ip_in_nets(ip, nets):
    """
        Test if ``ip`` is in one of the networks of ``nets``

        :param str ip: An ip, in dotted notation
        :param list nets: A list of :obj:`netaddr.IPNetwork`
        :return: ``True`` if ip is in one of the listed networks, ``False`` otherwise
        :rtype: bool
    """
    ip = netaddr.IPAddress(ip)
    for net in nets:
        if ip in net:
            return True
    return False


class PollableQueue(Queue.Queue):
    """
        A queue that can be watch using :func:`select.select`

        :param int maxsize: The maximum size on the queue. If maxsize is <= 0, the queue size is
            infinite.
    """

    #: A :class:`socket.socket` object ready for read then here is something to pull from the queue
    sock = None

    #: Internal socket that is written to then something is put on the queue
    _putsocket = None
    #: Alias of :attr:`sock`. Internal socket that is read from then something is pull from
    #: the queue
    _getsocket = None

    def __init__(self, maxsize=0):
        Queue.Queue.__init__(self, maxsize=maxsize)
        # Create a pair of connected sockets
        if os.name == 'posix':
            self._putsocket, self._getsocket = socket.socketpair()
        else:
            # Compatibility on non-POSIX systems
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            self._putsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._putsocket.connect(server.getsockname())
            self._getsocket, _ = server.accept()
            server.close()
        self._getsocket.setblocking(0)
        self._putsocket.setblocking(0)
        self.sock = self._getsocket

    def __del__(self):
        self._putsocket.close()
        self._getsocket.close()

    def _put(self, *args, **kwargs):
        Queue.Queue._put(self, *args, **kwargs)
        self._signal_put()

    def _signal_put(self):
        try:
            self._putsocket.send(b'x')
        except socket.error as error:
            if error.errno not in [11, 10035]:  # Resource temporarily unavailable
                raise

    def _comsume_get(self):
        try:
            self._getsocket.recv(1)
        except socket.error as error:
            # 11: Resource temporarily unavailable raised on unix system then nothing to read
            # 10035: raised on windows systems then nothing to read
            if error.errno not in [11, 10035]:
                raise

    def _get(self, *args, **kwargs):
        self._comsume_get()
        return Queue.Queue._get(self, *args, **kwargs)


class Scheduler(object):
    """
        Schedule weightless threads and DHTs io

        A weightless threads is a python callable returning an iterator that behave as describe
        next. The first returned value must be an integer describing the type of the iterator.
        0 means time based and all subsequent yield must return the next timestamp at which the
        iterator want to be called. 1 means queue based. The next call to the iterator must return
        an instance of :class:`PollableQueue`. All subsequent yield value are then ignored.
        The queue based iterator will be called when something is put on its queue.
    """

    #: map between an iterator and a unix timestamp representing the next time the iterator want to
    #: to be executed
    _time_based = {}
    #: map between an iterator and a queue processed by this iterator, processed by the main thread
    _queue_based = {}
    #: map between an iterator and a queue processed by this iterator, processed by the secondary
    #: thread
    _user_queue = {}
    #: A map between an iterator and its name
    _names = {}
    #: A map between its name and an iterator
    _iterators = {}

    #: A map between a :class:`PollableQueue` socket :attr:`PollableQueue.sock` and an iterator
    _queue_base_socket_map = {}
    #: A list of :attr:`PollableQueue.sock` to be processed on the main thread
    _queue_base_sockets = []
    #: A list of :attr:`PollableQueue.sock` to be processed on the secondary thread
    _user_queue_sockets = []

    #: A map between a :class:`dht.DHT_BASE.sock` and a :class:`dht.DHT_BASE` instance
    _dht_sockets = {}
    #: A map between the :attr:`PollableQueue.sock` socket of the :class:`dht.DHT_BASE.to_send`
    #: queue and a :class:`dht.DHT_BASE` instance
    _dht_to_send_sockets = {}
    #: A list of all keys of :attr`_dht_to_send_sockets` and :attr:`_dht_sockets`
    _dht_read_sockets = []

    def _dht_write_sockets(self):
        """
            Compute dynamically the list of socket we need to write to.
            All :class:`dht.DHT_BASE.sock` where :class:`dht.DHT_BASE.to_send` is not empty

            :return: A list of socket we want write to
            :rtype: list
        """
        try:
            return [s for (s, dht) in six.iteritems(self._dht_sockets) if not dht.to_send.empty()]
        except RuntimeError:
            return []

    _start_lock = None
    _threads = None
    _stoped = True

    def __init__(self):
        self._start_lock = Lock()
        self._init_attrs()
        self._threads = []

    def _init_attrs(self):
        """Ititialize the instance attributes"""
        self._time_based = {}
        self._queue_based = {}
        self._user_queue = {}
        self._names = {}
        self._queue_base_socket_map = {}
        self._queue_base_sockets = []
        self._user_queue_sockets = []
        self._iterators = {}

        self._dht_sockets = {}
        self._dht_to_send_sockets = {}
        self._dht_read_sockets = []


    def add_thread(self, name, function, user=False):
        """
            Schedule the call of weightless threads 

            :param str name: The name of the thread to add. Must be unique in the :class:`Scheduler`
                instance
            :param function: A weightless threads, i.e a callable returning an iterator
            :param bool user: If ``True`` the weightless threads is schedule in a secondary thread.
                The default is ``False`` and the weightless threads is processed in the main
                scheduler thread. This is usefull to put controled weightless threads and the main
                thread, and all the other (like the user defined on_``msg``_(query|response))
                function to the secondary one.

        """
        if name in self._iterators:
            raise ValueError("name already used")
        iterator = function()
        self._names[iterator] = name
        self._iterators[name] = iterator
        typ = iterator.next()
        if typ == 0:
            if user == True:
                raise ValueError("Only queue based threads can be put in the user loop")
            self._time_based[iterator] = 0
        elif typ == 1:
            queue = iterator.next()
            if user == True:
                self._user_queue[iterator] = queue
                self._user_queue_sockets.append(queue.sock)
            else:
                self._queue_based[iterator] = queue
                self._queue_base_sockets.append(queue.sock)
            self._queue_base_socket_map[queue.sock] = iterator
        else:
            raise RuntimeError("Unknown iterator type %s" % typ)

    def del_thread(self, name, stop_if_empty=True):
        """
            Remove the weightless threads named ``name``

            :param str name: The name of a thread
            :param bool stop_if_empty: If ``True`` (the default) and the scheduler has nothing to
                schedules, the scheduler will be stopped.
        """
        if name in self._iterators:
            iterator = self._iterators[name]
            try:
                del self._iterators[name]
            except KeyError:
                pass
            try:
                del self._names[iterator]
            except KeyError:
                pass
            try:
                del self._time_based[iterator]
            except KeyError:
                pass
            try:
                queue = self._queue_based[iterator]
                try:
                    del self._queue_base_socket_map[queue.sock]
                except KeyError:
                    pass
                try:
                    del self._queue_based[iterator]
                    self._queue_base_sockets.remove(queue.sock)
                except KeyError:
                    pass
                try:
                    del self._user_queue[iterator]
                    self._user_queue_sockets.remove(queue.sock)
                except KeyError:
                    pass
            except KeyError:
                pass
        if stop_if_empty and not self._dht_sockets and not self._iterators:
            self.stop_bg()

    def add_dht(self, dht):
        """
            Add a dht instance to be schedule by the scheduler

            :param dht.DHT_BASE dht: A dht instance
        """
        self._dht_sockets[dht.sock] = dht
        self._dht_to_send_sockets[dht.to_send.sock] = dht
        self._dht_read_sockets.append(dht.sock)
        self._dht_read_sockets.append(dht.to_send.sock)
        for (name, function, user) in dht.to_schedule:
            self.add_thread(name, function, user=user)

    def del_dht(self, dht):
        """
            Remove a dht instance from the scheduler

            :param dht.DHT_BASE dht: A dht instance
        """
        try:
            del self._dht_sockets[dht.sock]
        except KeyError:
            pass
        try:
            del self._dht_to_send_sockets[dht.to_send.sock]
        except KeyError:
            pass
        try:
            self._dht_read_sockets.remove(dht.sock)
        except ValueError:
            pass
        try:
            self._dht_read_sockets.remove(dht.to_send.sock)
        except ValueError:
            pass
        for (name, _, _) in dht.to_schedule:
            self.del_thread(name)

    def thread_alive(self, name):
        """
            Test is a weightless threads named ``name`` is currently schedule

            :param str name: The name of a thread
            :return: ``True`` if a thread of name ``name`` if found
            :rtype: bool
        """
        return self.is_alive() and name in self._iterators

    def is_alive(self):
        """Test if the scheduler main thread is alive

        :return: ``True`` the scheduler main thread is alive, ``False`` otherwise
        :rtype: bool
        """
        if self._threads and all([t.is_alive() for t in self._threads]):
            return True
        elif not self._threads and self._stoped:
            return False
        else:
            print("One thread died, stopping scheduler")
            self.stop(wait=False)
            return False

    def start(self, name_prefix="scheduler"):
        """
            start the scheduler

            :param str name_prefix: Prefix to the scheduler threads names
        """
        with self._start_lock:
            if not self._stoped:
                print("Already started")
                return
            if self.zombie:
                print("Zombie thread, unable de start")
                return self._threads
            self._stoped = False
        t = Thread(target=self._schedule_loop)
        t.setName("%s:schedule_loop" % name_prefix)
        t.daemon = True
        t.start()
        self._threads.append(t)
        t = Thread(target=self._schedule_user_loop)
        t.setName("%s:schedule_user_loop" % name_prefix)
        t.daemon = True
        t.start()
        self._threads.append(t)
        t = Thread(target=self._io_loop)
        t.setName("%s:io_loop" % name_prefix)
        t.daemon = True
        t.start()
        self._threads.append(t)

    def stop(self):
        """
            stop the scheduler

            :raises FailToStop: if we fail to stop one of the scheduler threads after 30 seconds
        """
        if self._stoped:
            print("Already stoped or stoping in progress")
            return
        self._stoped = True
        self._init_attrs()
        self._threads = [t for t in self._threads[:] if t.is_alive()]
        for i in range(0, 30):
            if self._threads:
                if i > 5:
                    print("Waiting for %s threads to terminate" % len(self._threads))
                time.sleep(1)
                self._threads = [t for t in self._threads[:] if t.is_alive()]
            else:
                break
        else:
            print("Unable to stop the scheduler threads, giving up")
        if self._threads:
            raise FailToStop(self._threads)

    def stop_bg(self):
        """Lauch the stop process of the dht and return immediately"""
        if not self._stoped:
            t=Thread(target=self.stop)
            t.daemon = True
            t.start()

    @property
    def zombie(self):
        """
            :return: ``True`` if the scheduler is stoped but its threads are still running
            :rtype: bool
        """
        return bool(self._stoped and [t for t in self._threads if t.is_alive()])

    def _schedule_loop(self):
        """The schedule loop calling weightless threads iterators then needed"""
        next_time = 0
        try:
            while True:

                if self._stoped:
                    return

                wait = max(0, next_time - time.time()) if self._time_based else 1

                # windows systems do not handle empty select
                if self._queue_base_sockets:
                    (sockets, _, _) = select.select(self._queue_base_sockets, [], [], wait)
                else:
                    sockets = []
                    time.sleep(wait)

                # processing time based threads
                if self._time_based:
                    now = time.time()
                    if now >= next_time:
                        to_set = []
                        try:
                            for iterator, t in six.iteritems(self._time_based):
                                if now >= t:
                                    to_set.append((iterator, iterator.next()))
                            for iterator, t in to_set:
                                self._time_based[iterator] = t
                        except RuntimeError:
                            pass
                        next_time = min(self._time_based.values())

                # processing queue based threads
                for sock in sockets:
                    try:
                        iterator = self._queue_base_socket_map[sock]
                        iterator.next()
                    except KeyError:
                        pass
        except StopIteration as error:
            try:
                print("Iterator %s stoped" % self._names[iterator])
                self.del_thread(self._names[iterator])
            except KeyError:
                pass

    def _schedule_user_loop(self):
        """
            A second schedule loop calling weightless threads iterators then needed

            These second loop is here to handle user defined function (on_``msg``_query and
            on_``msg``_response) than we do not known how long they can take, so they won't block
            the main loop :meth:`_schedule_loop`.
        """
        next_time = 0
        try:
            while True:

                if self._stoped:
                    return
                # windows systems do not handle empty select
                if self._user_queue_sockets:
                    (sockets, _, _) = select.select(self._user_queue_sockets, [], [], 1)
                else:
                    sockets = []
                    time.sleep(1)
                # processing queue based threads
                for sock in sockets:
                    try:
                        iterator = self._queue_base_socket_map[sock]
                        iterator.next()
                    except KeyError:
                        pass
        except StopIteration as error:
            try:
                print("Iterator %s stoped" % self._names[iterator])
                self.del_thread(self._names[iterator])
            except KeyError:
                pass

    def _io_loop(self):
        while True:
            if self._stoped:
                return
            try:
                # windows systems do not handle empty select
                if self._dht_read_sockets:
                    (sockets_read, sockets_write, _) = select.select(
                        self._dht_read_sockets, self._dht_write_sockets(), [], 0.1
                    )
                else:
                    sockets_read = []
                    sockets_write = []
                    time.sleep(0.1)
            except socket.error as e:
                self.debug(0, "recv:%r" %e )
                raise
            sockets_write = set(sockets_write)
            for sock in sockets_read:
                try:
                    if sock in self._dht_sockets:
                        dht = self._dht_sockets[sock]
                        if dht.stoped:
                            self.del_dht(dht)
                        else:
                            dht._process_incoming_message()
                    else:
                        dht = self._dht_to_send_sockets[sock]
                        if dht.stoped:
                            self.del_dht(dht)
                        elif dht.sock in sockets_write:
                            dht._process_outgoing_message()
                except KeyError:
                    pass
