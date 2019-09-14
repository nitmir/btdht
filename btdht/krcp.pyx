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

from libc cimport math
from libc.stdio cimport printf, sprintf
from libc.string cimport strlen, strncmp, strcmp, strncpy, strcpy
from libc.stdlib cimport atoi, atol, malloc, free
from cython.parallel import prange

import six

import utils
from .exceptions import MissingT, DecodeError

cdef int str_to_int(char* data, int len) nogil:
    """
        Transform a string of 1-9 to an int

        :param bytes data: A string with only character from 1 to 9
        :param in len: The length of data
        :return: The integer represented by ``data``
        :rtype: int

        Notes:
            We use atoi for the conversion so the integer must be a 32 bits signed integer.
            This function can be called without the python GIL
    """
    cdef char* msg = NULL
    cdef int i
    try:
        msg = <char *>malloc((len+1) * sizeof(char))
        strncpy(msg, data, len)
        msg[len]='\0'
        i = atoi(msg)
    finally:
        if msg != NULL:
            free(msg)
    return i

cdef long str_to_long(char* data, int len) nogil:
    """
        Transform a string of 1-9 to an int

        :param bytes data: A string with only character from 1 to 9
        :param in len: The length of data
        :return: The integer represented by ``data``
        :rtype: int

        Notes:
            We use atol for the conversion so the integer must be a 64 bits signed integer.
            This function can be called without the python GIL
    """
    cdef char* msg = NULL
    cdef long long i
    if data[0] == b'-' and len > 16 or len > 17:
        with gil:
            raise EnvironmentError(
                "Trying to convert %s to long long but it's too big" % data[:len]
            )
    try:
        msg = <char *>malloc((len+1) * sizeof(char))
        strncpy(msg, data, len)
        msg[len]=b'\0'
        i = atol(msg)
    finally:
        if msg != NULL:
            free(msg)
    return i

cdef int int_length(int i) nogil:
    """
        :param int i: An integer
        :return: The size of the string necessary to write an integer in decimal notation
        :rtype: int

        Notes:
            This function can be called without the python GIL
    """
    if i == 0:
        return 1
    elif i < 0:
        return (<int> math.log10(0-i)) + 2
    else:
        return (<int> math.log10(i)) + 1

cdef varray_to_list(char ** data, size):
    """
        Transform a an C array of compact peers information to a python list

        :param data: A C array of 6 length strings, each one representing a compact peers
            information
        :return: A python list of each elements of ``data``
        :rtype: list

        Note:
            Contact information in for peers is encoded as a 6-byte string.
            Also known as "Compact IP-address/port info" the 4-byte IP address
            is in network byte order with the 2 byte port in network byte order
            concatenated onto the end.
    """
    l=[]
    for i in range(size):
        l.append(data[i][:6])
    return l

cdef char** vlist_to_array(l, int size=6):
    """
        Transform a python list of compact peers information to a C array

        :param list l: A list of string of equals length
        :param int size: The length of the strings of ``l``
        :return: A C array of all of the elements of ``l``

        Notes:
            This function allocate a dynamic memory range (using malloc) for the returned array.
            You need to manually free the returned value to free the memory.
    """
    cdef char ** data = <char**>malloc(len(l) * sizeof(char*))
    for i in range(len(l)):
        if len(l[i]) != size:
            raise ValueError("list element should be of length %d\n" % size)
        data[i]=<char*>malloc(6 * sizeof(char))
        strncpy(data[i], l[i], 6)
    return data


cdef int _decode_pass_list(char* data, int *i, int max) nogil except -1:
    """
        Pass a bencoded list in a bencoded string

        :param bytes data: A bencoded string
        :param int[1] i: reference to the index on ``data`` we start reading
        :param int max: The length of ``data``
        :return bool: ``True`` if a bencoded list is successfully passed, then ``i`` is set
            to the index of the next bencoded object in ``data``, ``False`` otherwise.
        :rtype: bool
        :raises DecodeError: if failed to decode ``data``

        Notes:
            This function can be called without the python GIL
    """
    cdef int j[1]
    cdef long long ll[1]
    if i[0] >= max + 1:
        with gil:
            raise DecodeError("%s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b"l":
        return False
    i[0]+=1
    while data[i[0]] != b'e' and i[0] < max:
        if (
            not _decode_string(data, i, max, j) and
            not  _decode_int(data, i, max, ll) and
            not _decode_pass_list(data, i, max) and
            not _decode_pass_dict(data, i, max)
        ):
            with gil:
                raise DecodeError(
                    "Unable to parse one of the element of the list %d %r" % (i[0], data[:max])
                )
    if i[0] >= max:
        with gil:
            raise DecodeError("list_pass: %s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b'e':
        return False
    i[0]+=1
    return True

cdef int _decode_pass_dict(char* data, int *i, int max) nogil except -1:
    """
        Pass a bencoded dict in a bencoded string

        :param bytes data: A bencoded string
        :param int[1] i: reference to the index on ``data`` we start reading
        :param int max: The length of ``data``
        :return bool: ``True`` if a bencoded dict is successfully passed, then ``i`` is set
            to the index of the next bencoded object in ``data``, ``False`` otherwise.
        :rtype: bool
        :raises DecodeError: if failed to decode ``data``

        Notes:
            This function can be called without the python GIL
    """
    cdef int j[1]
    cdef long long ll[1]
    if i[0] >= max + 1:
        with gil:
            raise DecodeError("%s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b"d":
        return False
    i[0]+=1
    while data[i[0]] != b'e' and i[0] < max:
        if (
            not _decode_string(data, i, max, j) or
            (
                not _decode_string(data, i, max, j) and
                not _decode_int(data, i, max, ll) and
                not _decode_pass_list(data, i, max) and
                not _decode_pass_dict(data, i, max)
            )
        ):
            with gil:
                raise DecodeError(
                    "Unable to parse one of the element of the dict %d %r" % (i[0], data[:max])
                )
    if i[0] >= max:
        with gil:
            raise DecodeError("dict_pass: %s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b'e':
        return False
    i[0]+=1
    return True

cdef int _decode_string(char* data, int* i, int max, int* j) nogil except -1:
    """
        Pass a bencoded string in a bencoded string

        :param bytes data: A bencoded string
        :param int[1] i: reference to the index on ``data`` we start reading
        :param int max: The length of ``data``
        :return bool: ``True`` if a bencoded string is successfully passed, then ``i`` is set
            to the index of the next bencoded object in ``data``, ``False`` otherwise.
        :rtype: bool
        :raises DecodeError: if failed to decode ``data``

        Notes:
            This function can be called without the python GIL
    """
    cdef int ret
    if data[i[0]] == b'0' \
    or data[i[0]] == b'2' \
    or data[i[0]] == b'3' \
    or data[i[0]] == b'4' \
    or data[i[0]] == b'5' \
    or data[i[0]] == b'6' \
    or data[i[0]] == b'7' \
    or data[i[0]] == b'8' \
    or data[i[0]] == b'9' \
    or data[i[0]] == b'1':
        j[0]=i[0]+1
        while data[j[0]] != b':' and j[0] < max:
            j[0]+=1
        if data[j[0]] == b':':
            i[0] = j[0] + str_to_int(data + i[0], j[0]-i[0]) + 1
            j[0]+=1
            if i[0] <= max:
                return True
            else:
                with gil:
                     raise DecodeError("%s > %s : %r" % (i[0], max, data[:max]))
        else:
            with gil:
                raise DecodeError("%s != : at %s %r" % (data[j[0]], j[0], data[:max]))
    else:
        return False

cdef long _decode_int(char* data, int *i, int max, long long  *myint) nogil except -1:
    """
        Decode a bencoded int and write it to ``myint``

        :param bytes data: A bencoded string
        :param int[1] i: reference to the index on ``data`` we start reading
        :param int max: The length of ``data``
        :param int[1] myint: Where to write the decode dencoded int
        :return bool: ``True`` if a bencoded int is successfully decoded, then ``i`` is set
            to the index of the next bencoded object in ``data``, ``myint`` is set to the value of
            the decoded int. ``False`` otherwise.
        :rtype: bool
        :raises DecodeError: if failed to decode ``data``

        Warning:
           Use only if you are sure that int to decode is a signed 64bit integer
           otherwise, use the function from utils that can decode arbitrary long integer

        Notes:
            This function can be called without the python GIL
    """
    cdef int j
    if data[i[0]] == b'i':
        i[0]+=1
        j = i[0]
        while data[j] != b'e' and j < max:
            j+=1
        if data[j] == b'e':
            myint[0]=str_to_long(data + i[0], j-i[0])
            i[0]=j+1
            if i[0] <= max:
                return True
            else:
                with gil:
                     raise DecodeError("%s > %s : %r" % (i[0], max, data[:max]))
        else:
            with gil:
                raise DecodeError("%s != e at %s %r" % (data[j], j, data[:max]))
    else:
        return False

cdef int _encode_int(char* data, int *i, int max, int j) nogil:
    """
        Bencode the integer ``j``and write it in ``data`` at offset ``i``

        :param bytes data: A bencoded string
        :param int[1] i: The index of ``data`` we start writting to
        :param int max: The length of ``data``
        :param int j: The integer to bencode and write to data
        :return: ``True`` if ``j`` is successfully bencoded and written to ``data``, then ``i`` is
            set to the offset of ``data`` immediately after the bencoded int ``j``.  ``False``
            otherwise.
        :rtype: bool

        Notes:
            This function can be called without the python GIL
    """
    cdef int l
    l = int_length(j)
    if max >= i[0] + l + 2:
         data[i[0]]=b'i'
         i[0]+=1
         sprintf(data + i[0], b"%d", j)
         i[0]+=l
         data[i[0]]=b'e'
         i[0]+=1
         return True
    else:
        printf("encode_int: %d < %d\n", max, i[0] + l + 2)
        return False

cdef int _encode_string(char* data, int* i, int max, char* str, int strlen) nogil:
    """
        Bencode the string ``str`` of length ``ßtrlen`` and write it in ``data`` at offset ``i``

        :param bytes data: A bencoded string
        :param int[1] i: The index of ``data`` we start writting to
        :param int max: The length of ``data``
        :param bytes str: The string to bencode and write to data
        :param int strlen: The length of ``str``
        :return: ``True`` if ``str`` is successfully bencoded and written to ``data``, then ``i`` is
            set to the offset of ``data`` immediately after the bencoded string ``str``.  ``False``
            otherwise.
        :rtype: bool

        Notes:
            This function can be called without the python GIL
    """
    cdef int l
    l = int_length(strlen)
    if max >= i[0] + l + 1 + strlen: # size as char + : + string
        sprintf(data + i[0], b"%d", strlen)
        i[0]+=l
        data[i[0]]=b':'
        i[0]+=1
        strncpy(data + i[0], str, strlen)
        i[0]+=strlen
        return True
    else:
        printf("encode_string: %d < %d\n", max, i[0] + l + 1 + strlen)
        return False

class BError(Exception):
    """
        A base class exception for all bittorrent DHT protocol error exceptions

        :param bytes t: The value of the key t of the query for with the error is returned
        :param list e: A couple [error code, error message]
    """
    #: The ``y`` key of the error message. For an error message, it is always ``b"e"``
    y = b"e"
    #: string value representing a transaction ID, must be set to the query transaction ID
    #: for which an error is raises.
    t = None
    # A list. The first element is an :class:`int` representing the error code.
    # The second element is a string containing the error message
    e = None
    def __init__(self, t, e, **kwargs):
        if t is None:
            raise ValueError("t should not be None")
        self.t = t
        self.e = e
        super(BError, self).__init__(*e, **kwargs)

    def encode(self):
        """
            Bencode the error message

            :return: The bencoded error message ready to be send
            :rtype: bytes
        """
        return utils.bencode({b"y":self.y, b"t":self.t, b"e":self.e})

    def __str__(self):
        raise NotImplementedError()

    def __repr__(self):
        return "%s: %r" % (self.__class__.__name__, self.e)

class GenericError(BError):
    """
        A Generic Error, error code 201

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b""):
        super(GenericError, self).__init__(t=t, e=[201, msg])
class ServerError(BError):
    """
        A Server Error, error code 202

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b"Server Error"):
        super(ServerError, self).__init__(t=t, e=[202, msg])
class ProtocolError(BError):
    """
        A Protocol Error, such as a malformed packet, invalid arguments, or bad token,
        error code 203

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b"Protocol Error"):
        super(ProtocolError, self).__init__(t=t, e=[203, msg])
class MethodUnknownError(BError):
    """
        Method Unknown, error code 204

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b"Method Unknow"):
        super(MethodUnknownError, self).__init__(t=t, e=[204, msg])


cdef class BMessage:
    """
        A bittorrent DHT message. This class is able to bdecode a bittorrent DHT message. It
        expose then the messages keys ``t``, ``y``, ``q``,  ``errno``, ``errmsg`` and ``v`` as
        attributes, and behave itself as a dictionnary for the ``a`` or ``r`` keys that contains
        a secondary dictionnary (see Notes).

        :param tuple addr: An optionnal coupe (ip, port) of the sender of the message
        :param bool debug: ``True`` for enabling debug message. The default is ``False``

        Notes:
            A query message is always of the following form with ``y == b'q'``::

                {
                    "t": t,
                    "y": y,
                    "q": q, 
                    "a": {...}
                }

            A response message is always of the following form with ``y == b'r'``::

                {
                    "t": t,
                    "y": y,
                    "r": {...}
                }

            An error message is always in response of a query message and of the following form
            with ``y == b'e'``::

                {
                    "t": t,
                    "y": y,
                    "e":[errno, errmsg]
                }

            The ``t`` key is a random string generated with every query. It is used to match
            a response to a particular query.

            The ``y`` key is used to differenciate the type of the message. Its value is ``b'q'``
            for a query, ``b'r'`` for a response, and ``b'e'`` for and error message.

            The ``q`` is only present on query message and contain the name of the query (ping,
            get_peers, announce_peer, find_node)

            ``errno`` and ``errmsg`` are only defined if the message is an error message. They are
            respectively the error number (:class:`int`) and the error describing message of the error.

            The ``v`` key is set by some DHT clients to the name and version of the client and
            is totally optionnal in the protocol.
    """
    cdef int set_r(self, int value) nogil:
        """
            :param bool value: If ``True`` mark the current :class:`BMessage` as having a ``r`` dict
                (response dictionnary)

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        self.r = value
        return True

    cdef int set_a(self, int value) nogil:
        """
            :param bool value: If ``True`` mark the current :class:`BMessage` as a ``a`` dict
                (query dictionnary)

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        self.a = value
        return True

    cdef int set_e(self, int value) nogil:
        """
            :param bool value: If ``True`` mark the current :class:`BMessage` as an error,
                having a ``e`` list

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        self.e = value
        return True

    cdef int set_t(self, char* value, int size) nogil:
        """
            Set the ``t`` current message key to ``value``

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_t:
            free(self._t)
        else:
            self.has_t = True
        self._t = <char*>malloc(size * sizeof(char))
        self.t_len = size
        strncpy(self._t, value, size)
        return True

    cdef void del_t(self) nogil:
        """
            Unset the ``t`` current message key

            Notes:
                This method can be called without the python GIL
        """
        if self.has_t:
            self.encoded_uptodate = False
            self.has_t = False
            self.t_len = 0
            free(self._t)

    cdef int set_v(self, char* value, int size) nogil:
        """
            Set the ``v`` current message key to ``value``

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_v:
            free(self._v)
        else:
            self.has_v = True
        self._v = <char*>malloc(size * sizeof(char))
        self.v_len = size
        strncpy(self._v, value, size)
        return True

    cdef void del_v(self) nogil:
        """
            Unset the ``v`` current message key

            Notes:
                This method can be called without the python GIL
        """
        if self.has_v:
            self.encoded_uptodate = False
            self.has_v = False
            self.v_len = 0
            free(self._v)

    cdef int set_y(self, char* value, int size) nogil:
        """
            Set the ``y`` current message key to ``value``

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_y:
            free(self._y)
        else:
            self.has_y = True
        self._y = <char*>malloc(size * sizeof(char))
        self.y_len = size
        strncpy(self._y, value, size)
        return True

    cdef void del_y(self) nogil:
        """
            Unset the ``y`` current message key

            Notes:
                This method can be called without the python GIL
        """
        if self.has_y:
            self.encoded_uptodate = False
            self.has_y = False
            self.y_len = 0
            free(self._y)

    cdef int set_q(self, char* value, int size) nogil:
        """
            Set the ``q`` current message key to ``value``

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_q:
            free(self._q)
        else:
            self.has_q = True
        self._q = <char*>malloc(size * sizeof(char))
        self.q_len = size
        strncpy(self._q, value, size)
        return True

    cdef void del_q(self) nogil:
        """
            Unset the ``q`` current message key

            Notes:
                This method can be called without the python GIL
        """
        if self.has_q:
            self.encoded_uptodate = False
            self.has_q = False
            self.q_len = 0
            free(self._q)

    cdef int set_id(self, char* value, int size) nogil except -1:
        """
            Set the id of the message

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_id:
            free(self.id)
        else:
            self.has_id = True
        self.id = <char*>malloc(size * sizeof(char))
        strncpy(self.id, value, size)
        return True

    cdef void del_id(self) nogil:
        """
            Unset the id of the message

            Notes:
                This method can be called without the python GIL
        """
        if self.has_id:
            self.encoded_uptodate = False
            self.has_id = False
            free(self.id)

    cdef int set_target(self, char* value, int size) nogil except -1:
        """
            Set the target of the message

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_target:
            free(self.target)
        else:
            self.has_target = True
        self.target = <char*>malloc(size * sizeof(char))
        strncpy(self.target, value, size)
        return True

    cdef void del_target(self) nogil:
        """
            Unset the target of the message

            Notes:
                This method can be called without the python GIL
        """
        if self.has_target:
            self.has_target = False
            self.encoded_uptodate = False
            free(self.target)

    cdef int set_info_hash(self, char* value, int size) nogil except -1:
        """
            Set the info_hash of the message

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_info_hash:
            free(self.info_hash)
        else:
            self.has_info_hash = True
        self.info_hash = <char*>malloc(size * sizeof(char))
        strncpy(self.info_hash, value, size)
        return True

    cdef void del_info_hash(self) nogil:
        """
            Unset the info_hash of the message

            Notes:
                This method can be called without the python GIL
        """
        if self.has_info_hash:
            self.has_info_hash = False
            self.encoded_uptodate = False
            free(self.info_hash)

    cdef void del_implied_port(self) nogil:
        """
            Unset implied_port

            Notes:
                This method can be called without the python GIL
        """
        self.has_implied_port = False
        self.encoded_uptodate = False

    cdef int set_implied_port(self, int value) nogil:
        """
            Set implied_port to ``value``

            :param bool value: A boolean

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        self.implied_port = value
        self.has_implied_port = True
        return True

    cdef int set_port(self, int value) nogil:
        """
            Set port to ``value``

            :param int port: An integer

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        self.port = value
        self.has_port = True
        return True

    cdef void del_port(self) nogil:
        """
            Unset port attribut of th emessage

            Notes:
                This method can be called without the python GIL
        """
        self.has_port = False
        self.encoded_uptodate = False

    cdef int set_token(self, char* value, int size) nogil:
        """
            Set the token of the message

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_token:
            free(self.token)
        else:
            self.has_token = True
        self.token_len = size
        self.token = <char*>malloc(size * sizeof(char))
        strncpy(self.token, value, size)
        return True

    cdef void del_token(self) nogil:
        """
            Unset the token of the message

            Notes:
                This method can be called without the python GIL
        """
        if self.has_token:
            self.has_token = False
            self.encoded_uptodate = False
            self.token_len = 0
            free(self.token)

    cdef int set_nodes(self, char* value, int size) nogil:
        """
            Set the nodes attribute of the message

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.has_nodes:
            free(self.nodes)
        else:
            self.has_nodes = True
        self.nodes_len = size
        self.nodes = <char*>malloc(size * sizeof(char))
        strncpy(self.nodes, value, size)
        return True

    cdef int del_nodes(self) nogil:
        """
            Unset the nodes attribute of the message

            Notes:
                This method can be called without the python GIL
        """
        if self.has_nodes:
            self.has_nodes = False
            self.encoded_uptodate = False
            self.nodes_len = 0
            free(self.nodes)

    cdef int set_values(self, char** values, int nb) nogil:
        """
            Set the values of the message

            :param array value: An array of size ``nb`` of string of length 6
            :param int nb: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        cdef int i
        self.encoded_uptodate = False
        if self.has_values:
            for i in prange(self.values_nb):
                free(self.values[i])
            free(self.values)
        else:
            self.has_values = True
        self.values_nb = nb
        self.values = values
        return True

    cdef void del_values(self) nogil:
        """
            Unset the values of the messages

            Notes:
                This method can be called without the python GIL
        """
        cdef int i = 0
        if self.has_values:
            self.has_values = False
            self.encoded_uptodate = False
            for i in prange(self.values_nb):
                free(self.values[i])
            self.values_nb = 0
            free(self.values)

    cdef int set_errmsg(self, char* value, int size) nogil:
        """
            Set the errmsg attribute

            :param bytes value: A string
            :param int size: The length of ``value``

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        if self.errmsg_len > 0:
            free(self._errmsg)
        self.errmsg_len = size
        self._errmsg = <char*>malloc(size * sizeof(char))
        strncpy(self._errmsg, value, size)
        return True

    cdef void del_errmsg(self) nogil:
        """
            Unset the errmsg attribute

            Notes:
                This method can be called without the python GIL
        """
        if self.errmsg_len > 0:
            self.errmsg_len = 0
            self.encoded_uptodate = False
            free(self._errmsg)

    cdef int set_errno(self, int value) nogil:
        """
            Set the errno attribute

            :param int value: The error number to set

            Notes:
                This method can be called without the python GIL
        """
        self.encoded_uptodate = False
        self._errno = value
        return True

    cdef void del_encoded(self) nogil:
        """
            Mark the message as not encoded (invalided the cache of bencoded  string of the message)

            Notes:
                This method can be called without the python GIL
        """
        if self.encoded_len > 0:
            self.encoded_len = 0
            self.encoded_uptodate = False
            free(self.encoded)

    def response(self, dht):
        """
            If the message is a query, return the response message to send

            :param dht.DHT_BASE dht: The dht instance from which the message is originated
            :return: A :class:`BMessage` to send as response to the query
            :raises ProtocolError: if the query is malformated. To send as response to the querier
            :raises MethodUnknownError: If the RPC DHT method asked in the query is unknown.
                To send as response to the querier
        """
        cdef BMessage rep = BMessage()
        cdef char* id = NULL
        cdef int l1 = 0
        cdef int l2 = 0
        cdef char* nodes = NULL
        cdef char* token = NULL
        cdef char** values = NULL
        s = dht.myid.value
        id = s
        with nogil:
            if self.has_y and self.y_len == 1 and strncmp(self._y, b"q", 1) == 0:
                if self.has_q:
                    if self.q_len == 4 and strncmp(self._q, b"ping", 4) == 0:
                        rep.set_y(b"r", 1)
                        rep.set_t(self._t, self.t_len)
                        rep.set_r(True)
                        rep.set_id(id, 20)
                        self._encode()
                        with gil:
                            return rep
                    elif self.q_len == 9 and strncmp(self._q, b"find_nodes", 9) == 0:
                        if not self.has_target:
                            with gil:
                                raise ProtocolError(self.t, b"target missing")
                        rep.set_y(b"r", 1)
                        rep.set_t(self._t, self.t_len)
                        rep.set_r(True)
                        rep.set_id(id, 20)
                        with gil:
                            s = dht.get_closest_nodes(self.target[:20], compact=True)
                            nodes = s
                            l1 = len(nodes)
                        rep.set_nodes(nodes, l1)
                        self._encode()
                        with gil:
                            return rep
                    elif self.q_len == 9 and strncmp(self._q, b"get_peers", 9) == 0:
                        if not self.has_info_hash:
                            with gil:
                                raise ProtocolError(self.t, b"info_hash missing")
                        rep.set_y(b"r", 1)
                        rep.set_t(self._t, self.t_len)
                        rep.set_r(True)
                        rep.set_id(id, 20)
                        with gil:
                            s = dht._get_token(self.addr[0])
                            token = s
                            l1 = len(s)
                            s = dht._get_peers(self.info_hash[:20])
                            if s:
                                values = vlist_to_array(s)
                            else:
                                s = dht.get_closest_nodes(self.target[:20], compact=True)
                                nodes = s
                            l2 = len(s)
                        rep.set_token(token, l1)
                        if values != NULL:
                            rep.set_values(values, l2)
                        else:
                            rep.set_nodes(nodes, l2)
                        self._encode()
                        with gil:
                            return rep
                    elif self.q_len == 13 and strncmp(self._q, b"announce_peer", 13) == 0:
                        if not self.has_info_hash:
                            with gil:
                                raise ProtocolError(self.t, b"info_hash missing")
                        if not self.has_port:
                            with gil:
                                raise ProtocolError(self.t, b"port missing")
                        if not self.has_token:
                            with gil:
                                raise ProtocolError(self.t, b"token missing")
                        with gil:
                            s = dht._get_valid_token(self.addr[0])
                            if not self[b"token"] in s:
                                raise ProtocolError(self.t, b"bad token")
                        rep.set_y(b"r", 1)
                        rep.set_t(self._t, self.t_len)
                        rep.set_r(True)
                        rep.set_id(id, 20)
                        self._encode()
                        with gil:
                            return rep
                    else:
                        with gil:
                            raise MethodUnknownError(self.t, b"Method %s Unknown" % self.q)
                else:
                    printf("no rpc method name %d\n", 0)
            else:
                printf("not query %d\n", 1)

    cdef int _encode_values(self, char* data, int* i, int max) nogil:
        """
            If the values attribute of the message is set, bencode it in ``data``

            :param bytes data: A buffer string where we write to
            :param int[1] i: The index of ``data`` to start writting to
            :param int max: The length of ``data``
            :return: ``True`` if :attr:`values` is successfully bencoded and written to data, then
                ``i`` is set the the next free byte of ``data``. ``False`` otherwise.

            Notes:
                This method can be called without the python GIL
        """
        cdef int j
        if i[0] + self.values_nb * 8 + 2 > max:
            printf("encode_values: %d < %d\n", max, i[0] + self.values_nb * 8 + 2)
            return False
        data[i[0]]=b'l'
        i[0]+=1
        for j in prange(self.values_nb):
            #printf("encode value %d in encode_values\n", j)
            strncpy(data + i[0],"6:", 2)
            i[0]+=2
            strncpy(data + i[0], self.values[j], 6)
            i[0]+=6
        data[i[0]]=b'e'
        i[0]+=1
        return True

    cdef int _encode_secondary_dict(self, char* data, int* i, int max) nogil:
        """
            Bencode the secondary dictionnary of the message and write it to ``data``

            :param bytes data: A buffer string where we write to
            :param int[1] i: The index of ``data`` to start writting to
            :param int max: The length of ``data``
            :return: ``True`` if the secondary dictionnary is successfully bencoded and written
                to data, then ``i`` is set the the next free byte of ``data``. ``False`` otherwise.

            Notes:
                This method can be called without the python GIL

                A dht message is a dictionnary that always contain exactly a second dictionnary
                (except error messages). The method bencode this second dictionary.
                This second dictionnary is in the key ``"a"`` in a query message and in the key
                ``"r"`` of a response message.

                All attributes of the current message that should be in the secondary dictionnary
                are encoded in it if set.
                The following attributes are set to this dictionnary:
                    * id
                    * implied_port
                    * info_hash
                    * nodes
                    * port
                    * target
                    * token
                    * values

                    Note that all of this attributes should never all bet set in the same BMessage
                    although no mecanism is preventing you to do it.
        """
        if i[0] + 1 > max:
            printf("encode_secondary:%d\n", 0)
            return False
        data[i[0]] = b'd'
        i[0]+=1
        if self.has_id:
            if i[0] + 4 > max:
                printf("encode_secondary:%d\n", 1)
                return False
            strncpy(data + i[0], b"2:id", 4)
            i[0]+=4
            if not _encode_string(data, i, max, self.id, 20):
                return False
        if self.has_implied_port:
            if i[0] + 15 > max:
                printf("encode_secondary:%d\n", 2)
                return False
            strncpy(data + i[0], b"12:implied_port", 15)
            i[0]+=15
            if not _encode_int(data, i, max, self.implied_port):
                return False
        if self.has_info_hash:
            if i[0] + 11 > max:
                printf("encode_secondary:%d\n", 3)
                return False
            strncpy(data + i[0], b"9:info_hash", 11)
            i[0]+=11
            if not _encode_string(data, i, max, self.info_hash, 20):
                return False
        if self.has_nodes:
            if i[0] + 7 > max:
                printf("encode_secondary:%d\n", 4)
                return False
            strncpy(data + i[0], b"5:nodes", 7)
            i[0]+=7
            if not _encode_string(data, i, max, self.nodes, self.nodes_len):
                return False
        if self.has_port:
            if i[0] + 6 > max:
                printf("encode_secondary:%d\n", 5)
                return False
            strncpy(data + i[0], b"4:port", 6)
            i[0]+=6
            if not _encode_int(data, i, max, self.port):
                return False
        if self.has_target:
            if i[0] + 8 > max:
                printf("encode_secondary:%d\n", 6)
                return False
            strncpy(data + i[0], b"6:target", 8)
            i[0]+=8
            if not _encode_string(data, i, max, self.target, 20):
                return False
        if self.has_token:
            if i[0] + 7 > max:
                printf("encode_secondary:%d\n", 7)
                return False
            strncpy(data + i[0], b"5:token", 7)
            i[0]+=7
            if not _encode_string(data, i, max, self.token, self.token_len):
                return False
        if self.has_values:
            if i[0] + 8 > max:
                printf("encode_secondary:%d\n", 8)
                return False
            strncpy(data + i[0], b"6:values", 8)
            i[0]+=8
            if not self._encode_values(data, i, max):
                return False
        if i[0] + 1 > max:
            printf("encode_secondary:%d\n", 9)
            return False
        data[i[0]] = b'e'
        i[0]+=1
        return True

    cdef int _encode_error(self, char* data, int* i, int max) nogil:
        """
            Bencode the error list of an error message

            :param bytes data: A buffer string where we write to
            :param int[1] i: The index of ``data`` to start writting to
            :param int max: The length of ``data``
            :return: ``True`` if the error list is successfully bencoded and written
                to data, then ``i`` is set the the next free byte of ``data``. ``False`` otherwise.

            Notes:
                This method can be called without the python GIL

                All attributes of the current message that should be in the primary dictionnary
                are encoded in it if set.
                The following attributes are set to this dictionnary:
                    * q
                    * t
                    * v
                    * y

                    Moreover if ``a`` or ``r`` are set, the secondary dictionnary is bencoded
                    and added to the corresponding key. If ``e`` is set, the error list is bencoded
                    and added to the ``e`` key of the main dictionnary.

                    Note than ``a``, ``r`` and ``e`` are mutually exclusive and should not be set
                    together, although no mecanism is preventing you to do it.
        """
        if i[0] + 2 > max:
            printf("encode_error: %d", 0)
            return False
        data[i[0]] = b'l'
        i[0]+=1
        if not _encode_int(data, i, max, self._errno):
            return False
        if not _encode_string(data, i, max, self._errmsg, self.errmsg_len):
            return False
        if i[0] >= max:
            printf("encode_error: %d", 1)
            return False
        data[i[0]] = b'e'
        i[0]+=1
        return True

    cdef int _encode_main_dict(self, char* data, int* i, int max) nogil:
        """
            Bencode the message primary dictionnary

            :param bytes data: A buffer string where we write to
            :param int[1] i: The index of ``data`` to start writting to
            :param int max: The length of ``data``
            :return: ``True`` if the primary dictionnary is successfully bencoded and written
                to data, then ``i`` is set the the next free byte of ``data``. ``False`` otherwise.

            Notes:
                This method can be called without the python GIL
        """
        if i[0] + 1 > max:
            printf("encode_main: %d\n", 0)
            return False
        data[i[0]] = b'd'
        i[0]+=1
        if self.a:
            if i[0] + 3 > max:
                printf("encode_main: %d\n", 1)
                return False
            strncpy(data + i[0], b"1:a", 3)
            i[0]+=3
            if not self._encode_secondary_dict(data, i, max):
                return False
        if self.e:
            if i[0] + 3 > max:
                printf("encode_main: %d\n", 8)
                return False
            strncpy(data + i[0], b"1:e", 3)
            i[0]+=3
            if not self._encode_error(data, i, max):
                return False
        if self.has_q:
            if i[0] + 3 > max:
                printf("encode_main: %d\n", 2)
                return False
            strncpy(data + i[0], b"1:q", 3)
            i[0]+=3
            if not _encode_string(data, i, max, self._q, self.q_len):
                return False
        if self.r:
            if i[0] + 3 > max:
                printf("encode_main: %d\n", 3)
                return False
            strncpy(data + i[0], b"1:r", 3)
            i[0]+=3
            if not self._encode_secondary_dict(data, i, max):
                return False
        if self.has_t:
            if i[0] + 3 > max:
                printf("encode_main: %d\n", 4)
                return False
            strncpy(data + i[0], b"1:t", 3)
            i[0]+=3
            if not _encode_string(data, i, max, self._t, self.t_len):
                return False
        if self.has_v:
            if i[0] + 3 > max:
                printf("encode_main: %d\n", 5)
                return False
            strncpy(data + i[0], b"1:v", 3)
            i[0]+=3
            if not _encode_string(data, i, max, self._v, self.v_len):
                return False
        if self.has_y:
            if i[0] + 3 > max:
                printf("encode_main: %d %d\n", 6, i[0])
                return False
            strncpy(data + i[0], b"1:y", 3)
            i[0]+=3
            if not _encode_string(data, i, max, self._y, self.y_len):
                return False
        if i[0] + 1 > max:
            printf("encode_main: %d\n", 7)
            return False
        data[i[0]] = b'e'
        i[0]+=1
        return True


    cdef int _encode(self) nogil:
        """
            Bencode the current message

            :return: ``True`` if the message is successfully bencoded, ``False`` otherwise

            Notes:
                This method can be called without the python GIL
        """
        cdef int i=0
        if self.encoded_len > 0:
            free(self.encoded)
        self.encoded_len = self._encode_len()
        #printf("free%d\n", 0)
        #printf("free%d\n", 1)
        self.encoded = <char *> malloc(self.encoded_len * sizeof(char))
        if self._encode_main_dict(self.encoded, &i, self.encoded_len):
            self.encoded_uptodate = True
            return True
        else:
            free(self.encoded)
            self.encoded_len = 0
            self.encoded_uptodate = False
            return False

    cdef int _encode_len(self) nogil:
        """
            Compute the length of the message once bencoded

            :return: The length of the message once bencoded
            :rtype: int

            Notes:
                This method can be called without the python GIL

                This method is used to allocate the string buffer where the bencoded message
                will be written to.
        """
        cdef int estimated_len = 2 # the d and e of the global dict
        if self.has_y:
            estimated_len+=int_length(self.y_len) + 1 + self.y_len + 3# len + : + str
        if self.has_t:
            estimated_len+=int_length(self.t_len) + 1 + self.t_len + 3
        if self.has_q:
            estimated_len+=int_length(self.q_len) + 1 + self.q_len + 3
        if self.has_v:
            estimated_len+=int_length(self.v_len) + 1 + self.v_len + 3
        if self.r or self.a or self.e: # only one can be True
            estimated_len+=2 + 3 # the d and e of the a ou r dict
        if self.e:
            estimated_len+=(
                int_length(self._errno) + 2 +
                self.errmsg_len + 1 + int_length(self.errmsg_len)
            )
        if self.r or self.a:
            if self.has_id:
                estimated_len+=23 + 4
            if self.has_target:
                estimated_len+=23 + 8
            if self.has_info_hash:
                estimated_len+=23 + 11
            if self.has_implied_port:
                estimated_len+=int_length(self.implied_port) + 2 + 15# i + int + e
            if self.has_port:
                estimated_len+=int_length(self.port) + 2 + 6
            if self.has_nodes:
                estimated_len+=int_length(self.nodes_len) + 1 + self.nodes_len + 7
            if self.has_token:
                estimated_len+=int_length(self.token_len) + 1 + self.token_len + 7
            if self.has_values:
                estimated_len+= 8 * self.values_nb + 2 + 8 # l + nb * IPPORT + e
        #printf("estimated_len: %d\n" , estimated_len)
        return estimated_len

    def encode(self):
        """
            Bencoded the current message if necessary

            :return: The bencoded message
            :rtype: bytes
        """
        if self.encoded_uptodate:
                return self.encoded[:self.encoded_len]
        else:
            with nogil:
                self._encode()
        if self.encoded_uptodate:
                return self.encoded[:self.encoded_len]
        else:
            raise EnvironmentError("Unable to encode BMessage")

    def __repr__(self):
        return "%r" % self.encode()

    def __str__(self):
        raise NotImplementedError()

    #: The error number of the message if the message is and erro message
    property errno:
        def __get__(self):
            if self.e:
                return self._errno
            else:
                return None
        def __set__(self, int value):
            self.set_errno(value)

    #: The error message of the message if the message is and erro message
    property errmsg:
        def __get__(self):
            if self.e:
                return self._errmsg[:self.errmsg_len]
            else:
                return None
        def __set__(self, char* msg):
            l = len(msg)
            with nogil:
                self.set_errmsg(msg, l)

    #: The couple (ip, port) source of the message
    property addr:
        def __get__(self):
            if six.PY3:
                if self.addr_addr_3 and self.addr_port > 0:
                    return (self.addr_addr_3, self.addr_port)
                else:
                    return None
            else:
                if self.addr_addr_2 and self.addr_port > 0:
                    return (self.addr_addr_2, self.addr_port)
                else:
                    return None
        def __set__(self, addr):
            if addr is not None:
                if six.PY3:
                    self.addr_addr_3 = addr[0]
                else:
                    self.addr_addr_2 = addr[0]
                self.addr_port = addr[1]
        def __del__(self):
            self.addr_addr = None
            self.addr_port = 0

    #: The ``y` key of the message. Possible value are ``"q"`` for a query, `"r"` for a response
    #: and ``"e"`` for an error.
    property y:
        def __get__(self):
            if self.has_y:
                return self._y[:self.y_len]
            else:
                return None
        def __set__(self,char* value):
            l = len(value)
            with nogil:
                self.set_y(value, l)
        def __del__(self):
            with nogil:
                self.del_y()

    #: The ``t`` key, a random string, transaction id used to match queries and responses together.
    property t:
        def __get__(self):
            if self.has_t:
                return self._t[: self.t_len]
            else:
                return None
        def __set__(self,char* value):
            l = len(value)
            with nogil:
                self.set_t(value, l)
        def __del__(self):
            with nogil:
                self.del_t()

    #: The ``q`` key of the message, should only be define if the message is a query (:attr:`y` is
    #: ``"q"``). It countains the name of the RPC method the query is asking for. Can be
    #: ``b'ping'``, ``b'find_node'``, ``b'get_peers'``, ``b'announce_peer'``, ...
    property q:
        def __get__(self):
            if self.has_q:
                return self._q[: self.q_len]
            else:
                return None
        def __set__(self,char* value):
            l = len(value)
            with nogil:
                self.set_q(value, l)
        def __del__(self):
            with nogil:
                self.del_q()

    #: The ``v`` key of the message. This attribute is not describe in the BEP5 that describe the
    #: bittorent DHT protocol. It it use as a version flag. Many bittorent client set it to
    #: the name and version of the client.
    property v:
        def __get__(self):
            if self.has_v:
                return self._v[: self.v_len]
            else:
                return None
        def __set__(self,char* value):
            l = len(value)
            with nogil:
                self.set_v(value, l)

        def __del__(self):
            with nogil:
                self.del_v()

    def __getitem__(self, char* key):
        """
            Allow to fetch infos from the secondary dictionnary::

                self[b"id"] -> b"..."

            :param bytes key: The name of an attribute of the secondary dictionnary to retreive.
            :return: The value store for ``key`` if found
            :raises KeyError: if ``key`` is not found

            Notes:
                Possible keys are:
                  * id
                  * target
                  * info_hash
                  * token
                  * nodes
                  * implied_port
                  * port
                  * values
        """
        if key == b"id" and self.has_id:
            return self.id[:20]
        elif key == b"target" and self.has_target:
            return self.target[:20]
        elif key == b"info_hash" and self.has_info_hash:
            return self.info_hash[:20]
        elif key == b"token" and self.has_token:
            return self.token[:self.token_len]
        elif key == b"nodes" and self.has_nodes:
            return self.nodes[:self.nodes_len]
        elif key == b"implied_port" and self.has_implied_port:
            return self.implied_port
        elif key == b"port" and self.has_port:
            return self.port
        elif key == b"values" and self.has_values:
            return varray_to_list(self.values, self.values_nb)
        else:
            raise KeyError(key)

    def __delitem__(self, char* key):
        """
            Allow to unset attributes from the secondary dictionnary::

                del self[b'id']

            :param :param bytes key: The name of an attribute of the secondary dictionnary to unset
            :return: ``True`` if ``key`` is found and successfully unset
            :raise KeyError: if ``key`` is not found
        """
        with nogil:
            if self.has_id and strcmp(key, b"id") == 0:
                self.del_id()
            elif self.has_target and strcmp(key, b"target") == 0:
                self.del_target()
            elif self.has_info_hash and strcmp(key, b"info_hash") == 0:
                self.del_info_hash()
            elif self.has_token and strcmp(key, b"token") == 0:
                self.del_token()
            elif self.has_nodes and strcmp(key, b"nodes") == 0:
                self.del_nodes()
            elif self.has_implied_port and strcmp(key, b"implied_port") == 0:
                self.del_implied_port()
            elif self.has_port and strcmp(key, b"port") == 0:
                self.del_port()
            elif self.has_values and strcmp(key, b"values") == 0:
                self.del_values()
            else:
                with gil:
                    raise KeyError(key)

    def __setitem__(self, char* key, value):
        """
            Allow to set attributes from the secondary dictionnary::

                self[b'id'] = b"..."

            :param bytes key: The name of an attribute of the secondary dictionnary to set
            :param value: The value to set
            :raises KeyError: if ``key`` is not one of id, target, info_hash, token, nodes,
                implied_port, port, values.
            :raises ValueError: if ``value`` is not well formated (length, type, ...)
        """
        cdef int i = 0
        cdef char * j
        cdef char** v
        cdef int l = 0
        with nogil:
            if strcmp(key, b"id") == 0:
                with gil:
                    if len(value) != 20:
                        raise ValueError("Can only set strings of length 20B")
                    j = value
                self.set_id(j, 20)
                return
            elif strcmp(key, b"target") == 0:
                self.encoded_uptodate = False
                with gil:
                    if len(value) != 20:
                        raise ValueError("Can only set strings of length 20B")
                    j = value
                self.set_target(j, 20)
                return
            elif strcmp(key, b"info_hash") == 0:
                with gil:
                    if len(value) != 20:
                        raise ValueError("Can only set strings of length 20B")
                    j = value
                self.set_info_hash(j, 20)
                return
            elif strcmp(key, b"token") == 0:
                with gil:
                    l = len(value)
                    j = value
                self.set_token(j, l)
                return
            elif strcmp(key, b"nodes") == 0:
                with gil:
                    l = len(value)
                    j = value
                self.set_nodes(j, l)
                return
            elif strcmp(key, b"implied_port") == 0:
                with gil:
                    i = value
                self.set_implied_port(i)
                return
            elif strcmp(key, b"port") == 0:
                with gil:
                    i = value
                self.set_port(i)
                return
            elif strcmp(key, b"values") == 0:
                with gil:
                    v = vlist_to_array(value)
                    i = len(value)
                self.set_values(v, i)
                return
        raise KeyError(key)

    def get(self, char* key, default=None):
        """
            :param bytes key: The name of an attribute of the secondary dictionnary to retreive.
            :param default: Value to return in case ``key`` is not found. The default is ``None``
            :return: The value of ``key`` if found, else the value of ``default``.
        """
        try:
            return self[key]
        except KeyError as e:
            return default

    def __dealloc__(self):
        """
            Called before removal of the object.
            Used to free manually allocated memory
        """
        cdef int i
        with nogil:
            free(self._y)
            free(self._t)
            free(self._q)
            free(self._v)
            free(self.id)
            free(self.target)
            free(self.info_hash)
            free(self.token)
            free(self.nodes)
            free(self.encoded)
            for i in prange(self.values_nb):
                free(self.values[i])
            free(self.values)
            free(self._errmsg)

    cdef int _decode_error(self, char* data, int* i, int max) nogil except -1:
        """
            Decode and error bencoded list from ``data[i:]`` and set the message attributes errorno
            and errormsg.

            :param bytes data: The bencoded string to decode
            :param int[1] i: The offset of ``data`` to start decoding from
            :param int max: The length of data
            :return: ``True`` if the error list is successfully decoded, ``False`` otherwise

            Notes:
                This method can be called without the python GIL
        """
        cdef int j[1]
        cdef long long ll[1]
        if i[0] > max:
            with gil:
                raise DecodeError("%s > %s : %r" % (i[0], max, data[:max]))
        if data[i[0]] != b'l':
            return False
        i[0]+=1
        if not _decode_int(data, i, max, ll):
            return False
        self.set_errno(ll[0])
        if not _decode_string(data, i, max, j):
            return False
        self.set_errmsg(data + j[0], i[0]-j[0])
        if data[i[0]] != b'e':
            return False
        i[0]+=1
        return True

    cdef int _decode_dict_elm(self, char* data, int* i, int max) nogil except -1:
        """
            Decode a dictionnary element: a key and a value. Set the corresponding attributes
            on the message.

            :param bytes data: The bencoded string to decode
            :param int[1] i: The offset of ``data`` to start decoding from
            :param int max: The length of data
            :return: ``False`` if the decoding failed. ``True`` otherwise.

            Notes:
                This method can be called without the python GIL

                If one decoded element is successfully decoded but has a bad value or format or type
                the :attr:`failed` attribute is set to ``True`` and :attr:`failed_msg` is set to
                and error message. An error is then raises later. This is usefull for trying to
                decode the ``"t"`` key in the dictionnary so we can send an error message to
                the source of the errored message. As keys in bencoded dictionnary is alphanumeri-
                cally sorted, t is often at the end of the message and thus, even is a bad value is
                found, we must keep decoding the message at lest until we found its ``"t"``.
        """
        cdef char* error
        cdef int j[1]
        cdef long long ll[1]
        j[0]=0
        if not _decode_string(data, i, max, j):
            with gil:
                raise DecodeError("Fail to decode dict key %d %s" % (i[0], data[:max]))

        if (i[0]-j[0]) == 1 and strncmp(data + j[0], b"a", i[0]-j[0]) == 0:
            return self._decode_dict(data, i, max) and self.set_a(True)
        elif (i[0]-j[0]) == 1 and strncmp(data + j[0], b"r", i[0]-j[0]) == 0:
            return self._decode_dict(data, i, max) and self.set_r(True)
        elif (i[0]-j[0]) == 1 and strncmp(data + j[0], b"e", i[0]-j[0]) == 0:
            return self._decode_error(data, i, max) and self.set_e(True)
        elif (i[0]-j[0]) == 1 and strncmp(data + j[0], b"t", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_t(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 1 and strncmp(data + j[0], b"v", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_v(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 1 and strncmp(data + j[0], b"y", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_y(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 1 and strncmp(data + j[0], b"q", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_q(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 2 and strncmp(data + j[0], b"id", i[0]-j[0]) == 0:
            if _decode_string(data, i, max, j):
                if i[0]-j[0] != 20:
                    self.failed = True
                    self.failed_msg = b"id should be of length 20"
                return self.set_id(data + j[0], i[0]-j[0])
            else:
                return False
        elif (i[0]-j[0]) == 6 and strncmp(data + j[0], b"target", i[0]-j[0]) == 0:
            if _decode_string(data, i, max, j):
                if i[0]-j[0] != 20:
                    self.failed = True
                    self.failed_msg = b"target should be of length 20"
                return self.set_target(data + j[0], i[0]-j[0])
            else:
                return False
        elif (i[0]-j[0]) == 9 and strncmp(data + j[0], b"info_hash", i[0]-j[0]) == 0:
            if _decode_string(data, i, max, j):
                if i[0]-j[0] != 20:
                    self.failed = True
                    self.failed_msg = b"info_hash should be of length 20"
                return self.set_info_hash(data + j[0], i[0]-j[0])
            else:
                return False
        elif (i[0]-j[0]) == 12 and strncmp(data + j[0], b"implied_port", i[0]-j[0]) == 0:
            return _decode_int(data, i, max, ll) and self.set_implied_port(ll[0])
        elif (i[0]-j[0]) == 4 and strncmp(data + j[0], b"port", i[0]-j[0]) == 0:
            return _decode_int(data, i, max, ll) and self.set_port(ll[0])
        elif (i[0]-j[0]) == 5 and strncmp(data + j[0], b"token", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_token(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 5 and strncmp(data + j[0], b"nodes", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_nodes(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 6 and strncmp(data + j[0], b"values", i[0]-j[0]) == 0:
            if self._decode_values(data, i, max):
                return True
            else:
                self.failed = True
                self.failed_msg = b"values items should be a list"
        #if self.debug:
        #    error = <char*>malloc((i[0] + 1 - j[0]) * sizeof(char))
        #    error[i[0]-j[0]]='\0'
        #    strncpy(error, data + j[0], i[0] - j[0])
        #    printf("error %s\n", error)
        #    free(error)
        if _decode_string(data, i, max, j):
            return True
        if _decode_int(data, i, max, ll):
            return True
        if _decode_pass_list(data, i, max):
            return True
        if _decode_pass_dict(data, i, max):
            return True

        with gil:
            raise DecodeError("Unable to decode element of dict at %d %r" % (j[0], data[:max]))

    cdef int _decode_values(self, char* data, int *i, int max) nogil except -1:
        """
            Bdecode a values list of peers in compact forms (6 Bytes, 4 for ip and 2 for port)

            :param bytes data: The bencoded string to decode
            :param int[1] i: The offset of ``data`` to start decoding from
            :param int max: The length of data
            :return: ``False`` if ``data[i]`` do not point a list. ``True`` otherwise.
            :raises DecodeError: if we reach the end of ``data`` before the end of the list

            Notes:
                This method can be called without the python GIL

                If one decoded element is successfully decoded but has a bad value or format or type
                the :attr:`failed` attribute is set to ``True`` and :attr:`failed_msg` is set to
                and error message. See :meth:`_decode_dict_elm` for more details why.
        """
        cdef int j[1]
        cdef int c = 0
        cdef int k = i[0] + 1
        cdef char** values
        if i[0] >= max:
            with gil:
                raise DecodeError("%s > %s : %r" % (i[0], max, data[:max]))
        if not data[i[0]] == b'l':
            return False
        i[0]+=1
        while _decode_string(data, i, max, j):
            if (i[0]-j[0]) != 6:
                self.failed = True
                self.failed_msg = b"element of values are expected to be of length 6"
            c+=1
        if i[0] >=  max or data[i[0]] != b'e':
            with gil:
                raise DecodeError(
                    "End of values list not found %s >= %s found %s elements" % (i[0], max, c)
                )
        i[0] = k
        values = <char **>malloc(c * sizeof(char*))
        c=0
        while _decode_string(data, i, max, j):
           values[c] = <char *>malloc( 6 * sizeof(char))
           strncpy(values[c], data + j[0], 6)
           c+=1
        self.set_values(values, c)
        i[0]+=1
        return True

    cdef int _decode_dict(self, char* data, int *i, int max) nogil except -1:
        """
            Bdecode a dictionnary, element by element.

            :param bytes data: The bencoded string to decode
            :param int[1] i: The offset of ``data`` to start decoding from
            :param int max: The length of data
            :raises DecodeError: if we reach the end of ``data`` before the end of the list or
                fail to decode one of the dict elements.

            Notes:
                This method can be called without the python GIL
        """
        cdef int k
        if data[i[0]] == b'd':
            i[0]+=1
            while data[i[0]] != b'e' and i[0] < max:
                k = i[0]
                if not self._decode_dict_elm(data, i, max):
                    with gil:
                        raise DecodeError("fail to decode dict element %d %r" % (k, data[:max]))
        if data[i[0]] != b'e':
            with gil:
                raise DecodeError("End of dict not found %s>=%d %r" % (i[0], max, data[:max]))
        else:
            i[0]+=1
            return True

    cdef int _decode(self, char* data, int *i, int max) nogil except -1:
        """
            Bdecode a bencoded message and set the current :class:`BMessage` attributes accordingly

            :param bytes data: The bencoded string to decode
            :param int[1] i: The offset of ``data`` to start decoding from
            :param int max: The length of data

            Notes:
                This method can be called without the python GIL
        """
        return self._decode_dict(data, i, max)

    def  __init__(self, addr=None, debug=False):
        self.addr = addr

    def __cinit__(self, addr=None, debug=False):
        self.debug = True if debug else False
        with nogil:
            self.values_nb = 0
            self.errmsg_len = 0
            self.encoded_len = 0
            self.r = False
            self.a = False
            self.e = False
            self.failed = False
            self.has_y = False
            self.has_t = False
            self.has_q = False
            self.has_v = False
            self.has_id = False
            self.has_target = False
            self.has_info_hash = False
            self.has_token = False
            self.has_nodes = False
            self.has_values = False
            self.encoded_uptodate = False

    def decode(self, char* data, int datalen):
        """
            Bdecode a bencoded message and set the current :class:`BMessage` attributes accordingly

            :param bytes data: The bencoded message
            :param int datalen: The length of ``data``
            :return: The remaining of ``data`` after the first bencoded message of ``data`` has been
                bdecoded (it may be the empty string if ``data`` contains exactly one bencoded
                message with no garbade at the end).
            :raises DecodeError: If we fail to decode the message
            :raises ProtocolError: If the message is decoded but some attributes are missing of
                badly formated (length, type, ...).
            :raises MissingT: If the message do not have a ``b"t"`` key. Indeed,
                accordingly to the BEP5, every message (queries, responses, errors) should have
                a ``b"t"`` key.
        """
        cdef int i = 0
        cdef int valid = False
        with nogil:
            if datalen > 0:
                valid = self._decode(data, &i, datalen)
                if not self.has_t:
                    with gil:
                        raise MissingT()
                if self.failed:
                    if self.has_y and strncmp(self._y, b"q", 1):
                        with gil:
                            raise ProtocolError(self.t, self.failed_msg)
                    else:
                        with gil:
                          raise DecodeError(self.failed_msg)
                if not valid or not self.has_y:
                    if self.has_y and strncmp(self._y, b"q", 1):
                        with gil:
                            raise ProtocolError(self.t)
                    else:
                        with gil:
                            raise DecodeError()
        return data[i:]
