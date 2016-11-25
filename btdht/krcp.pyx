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

from libc cimport math
from libc.stdio cimport printf, sprintf
from libc.string cimport strlen, strncmp, strcmp, strncpy, strcpy
from libc.stdlib cimport atoi, atoll, malloc, free
from cython.parallel import prange

import six

from btdht import utils

cdef int str_to_int(char* data, int len) nogil:
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

cdef int str_to_long_long(char* data, int len) nogil:
    cdef char* msg = NULL
    cdef long long i
    if data[0] == b'-' and len > 16 or len > 17:
        with gil:
            raise EnvironmentError("Trying to convert %s to long long but it's too big" % data[:len])
    try:
        msg = <char *>malloc((len+1) * sizeof(char))
        strncpy(msg, data, len)
        msg[len]=b'\0'
        i = atoll(msg)
    finally:
        if msg != NULL:
            free(msg)
    return i

cdef int int_length(int i) nogil:
    if i == 0:
        return 1
    elif i < 0:
        return (<int> math.log10(0-i)) + 2
    else:
        return (<int> math.log10(i)) + 1

cdef varray_to_list(char ** data, size):
    l=[]
    for i in range(size):
        l.append(data[i][:6])
    return l

cdef char** vlist_to_array(l, int size=6):
    cdef char ** data = <char**>malloc(len(l) * sizeof(char*))
    for i in range(len(l)):
        if len(l[i]) != size:
            raise ValueError("list element should be of length %d\n" % size)
        data[i]=<char*>malloc(6 * sizeof(char))
        strncpy(data[i], l[i], 6)
    return data


cdef int _decode_pass_list(char* data, int *i, int max) nogil except -1:
    cdef int j[0]
    cdef long long ll[0]
    if i[0] >= max + 1:
        with gil:
            raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b"l":
        return False
    i[0]+=1
    while data[i[0]] != b'e' and i[0] < max:
        if not _decode_string(data, i, max, j) and not  _decode_int(data, i, max, ll) and not _decode_pass_list(data, i, max) and not _decode_pass_dict(data, i, max):
            with gil:
                raise ValueError("Unable to parse one of the element of the list %d %r" % (i[0], data[:max]))
    if i[0] >= max:
        with gil:
            raise ValueError("list_pass: %s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b'e':
        return False
    i[0]+=1
    return True

cdef int _decode_pass_dict(char* data, int *i, int max) nogil except -1:
    cdef int j[0]
    cdef long long ll[0]
    if i[0] >= max + 1:
        with gil:
            raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b"d":
        return False
    i[0]+=1
    while data[i[0]] != b'e' and i[0] < max:
        if not _decode_string(data, i, max, j) or (not _decode_string(data, i, max, j) and not _decode_int(data, i, max, ll) and not _decode_pass_list(data, i, max) and not _decode_pass_dict(data, i, max)):
            with gil:
                raise ValueError("Unable to parse one of the element of the dict %d %r" % (i[0], data[:max]))
    if i[0] >= max:
        with gil:
            raise ValueError("dict_pass: %s > %s : %r" % (i[0], max, data[:max]))
    if data[i[0]] != b'e':
        return False
    i[0]+=1
    return True

cdef int _decode_string(char* data, int* i, int max, int* j) nogil except -1:
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
                     raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
        else:
            with gil:
                raise ValueError("%s != : at %s %r" % (data[j[0]], j[0], data[:max]))
    else:
        return False

cdef int _decode_int(char* data, int *i, int max, long long  *myint) nogil except -1:
    """
       warning ! use only if you are sure that int to decode fetch in a signed 64bit integer
       otherwise, use the function from utils that can decode arbitrary long integer
    """
    cdef int j
    if data[i[0]] == b'i':
        i[0]+=1
        j = i[0]
        while data[j] != b'e' and j < max:
            j+=1
        if data[j] == b'e':
            myint[0]=str_to_long_long(data + i[0], j-i[0])
            i[0]=j+1
            if i[0] <= max:
                return True
            else:
                with gil:
                     raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
        else:
            with gil:
                raise ValueError("%s != e at %s %r" % (data[j], j, data[:max]))
    else:
        return False

cdef int _encode_int(char* data, int *i, int max, int j) nogil:
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
    y = b"e"
    t = None # string value representing a transaction ID
    e = None # a list. The first element is an integer representing the error code. The second element is a string containing the error message
    def __init__(self, t, e, **kwargs):
        if t is None:
            raise ValueError("t should not be None")
        self.t = t
        self.e = e
        super(BError, self).__init__(*e, **kwargs)

    def encode(self):
        return utils.bencode({b"y":self.y, b"t":self.t, b"e":self.e})

    def __str__(self):
        raise NotImplementedError()

    def __repr__(self):
        return "%s: %r" % (self.__class__.__name__, self.e)

class GenericError(BError):
    def __init__(self, t, msg=b""):
        super(GenericError, self).__init__(t=t, e=[201, msg])
class ServerError(BError):
    def __init__(self, t, msg=b"Server Error"):
        super(ServerError, self).__init__(t=t, e=[202, msg])
class ProtocolError(BError):
    def __init__(self, t, msg=b"Protocol Error"):
        super(ProtocolError, self).__init__(t=t, e=[203, msg])
class MethodUnknownError(BError):
    def __init__(self, t, msg=b"Method Unknow"):
        super(MethodUnknownError, self).__init__(t=t, e=[204, msg])


cdef class BMessage:
    cdef int set_r(self, int value) nogil:
        self.encoded_uptodate = False
        self.r = value
        return True

    cdef int set_a(self, int value) nogil:
        self.encoded_uptodate = False
        self.a = value
        return True

    cdef int set_e(self, int value) nogil:
        self.encoded_uptodate = False
        self.e = value
        return True

    cdef int set_t(self, char* value, int size) nogil:
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
        if self.has_t:
            self.encoded_uptodate = False
            self.has_t = False
            self.t_len = 0
            free(self._t)

    cdef int set_v(self, char* value, int size) nogil:
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
        if self.has_v:
            self.encoded_uptodate = False
            self.has_v = False
            self.v_len = 0
            free(self._v)

    cdef int set_y(self, char* value, int size) nogil:
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
        if self.has_y:
            self.encoded_uptodate = False
            self.has_y = False
            self.y_len = 0
            free(self._y)

    cdef int set_q(self, char* value, int size) nogil:
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
        if self.has_q:
            self.encoded_uptodate = False
            self.has_q = False
            self.q_len = 0
            free(self._q)

    cdef int set_id(self, char* value, int size) nogil except -1:
        if size != 20:
            with gil:
                raise ValueError("id must be 20B long")
        self.encoded_uptodate = False
        if self.has_id:
            free(self.id)
        else:
            self.has_id = True
        self.id = <char*>malloc(size * sizeof(char))
        strncpy(self.id, value, size)
        return True

    cdef void del_id(self) nogil:
        if self.has_id:
            self.encoded_uptodate = False
            self.has_id = False
            free(self.id)

    cdef int set_target(self, char* value, int size) nogil except -1:
        if size != 20:
            with gil:
                raise ValueError("id must be 20B long")
        self.encoded_uptodate = False
        if self.has_target:
            free(self.target)
        else:
            self.has_target = True
        self.target = <char*>malloc(size * sizeof(char))
        strncpy(self.target, value, size)
        return True

    cdef void del_target(self) nogil:
        if self.has_target:
            self.has_target = False
            self.encoded_uptodate = False
            free(self.target)

    cdef int set_info_hash(self, char* value, int size) nogil except -1:
        if size != 20:
            with gil:
                raise ValueError("id must be 20B long")
        self.encoded_uptodate = False
        if self.has_info_hash:
            free(self.info_hash)
        else:
            self.has_info_hash = True
        self.info_hash = <char*>malloc(size * sizeof(char))
        strncpy(self.info_hash, value, size)
        return True

    cdef void del_info_hash(self) nogil:
        if self.has_info_hash:
            self.has_info_hash = False
            self.encoded_uptodate = False
            free(self.info_hash)

    cdef void del_implied_port(self) nogil:
        self.has_implied_port = False
        self.encoded_uptodate = False

    cdef int set_implied_port(self, int value) nogil:
        self.encoded_uptodate = False
        self.implied_port = value
        self.has_implied_port = True
        return True

    cdef int set_port(self, int value) nogil:
        self.encoded_uptodate = False
        self.port = value
        self.has_port = True
        return True

    cdef void del_port(self) nogil:
        self.has_port = False
        self.encoded_uptodate = False

    cdef int set_token(self, char* value, int size) nogil:
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
        if self.has_token:
            self.has_token = False
            self.encoded_uptodate = False
            self.token_len = 0
            free(self.token)

    cdef int set_nodes(self, char* value, int size) nogil:
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
        if self.has_nodes:
            self.has_nodes = False
            self.encoded_uptodate = False
            self.nodes_len = 0
            free(self.nodes)

    cdef int set_values(self, char** values, int nb) nogil:
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
        cdef int i = 0
        if self.has_values:
            self.has_values = False
            self.encoded_uptodate = False
            for i in prange(self.values_nb):
                free(self.values[i])
            self.values_nb = 0
            free(self.values)

    cdef int set_errmsg(self, char* value, int size) nogil:
        self.encoded_uptodate = False
        if self.errmsg_len > 0:
            free(self._errmsg)
        self.errmsg_len = size
        self._errmsg = <char*>malloc(size * sizeof(char))
        strncpy(self._errmsg, value, size)
        return True

    cdef void del_errmsg(self) nogil:
        if self.errmsg_len > 0:
            self.errmsg_len = 0
            self.encoded_uptodate = False
            free(self._errmsg)

    cdef int set_errno(self, int value) nogil:
        self.encoded_uptodate = False
        self._errno = value
        return True

    cdef void del_encoded(self) nogil:
        if self.encoded_len > 0:
            self.encoded_len = 0
            self.encoded_uptodate = False
            free(self.encoded)

    def response(self, dht):
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
            estimated_len+=int_length(self._errno) + 2 + self.errmsg_len + 1 + int_length(self.errmsg_len)
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

    property errno:
        def __get__(self):
            if self.e:
                return self._errno
            else:
                return None
        def __set__(self, int value):
            self.set_errno(value)

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

    property addr:
        def __get__(self):
            if six.PY3:
                if self.addr_addr_3 and self.addr_port:
                    return (self.addr_addr_3, self.addr_port)
                else:
                    return None
            else:
                if self.addr_addr_2 and self.addr_port:
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
            self.addr_port = None

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
        try:
            return self[key]
        except KeyError as e:
            return default

    def __dealloc__(self):
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
        cdef int j[1]
        cdef long long ll[1]
        if i[0] > max:
            with gil:
                raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
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
        cdef char* error
        cdef int j[1]
        cdef long long ll[1]
        j[0]=0
        if not _decode_string(data, i, max, j):
            with gil:
                raise ValueError("Fail to decode dict key %d %s" % (i[0], data[:max]))

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
            return _decode_string(data, i, max, j) and self.set_id(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 6 and strncmp(data + j[0], b"target", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_target(data + j[0], i[0]-j[0])
        elif (i[0]-j[0]) == 9 and strncmp(data + j[0], b"info_hash", i[0]-j[0]) == 0:
            return _decode_string(data, i, max, j) and self.set_info_hash(data + j[0], i[0]-j[0])
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
                with gil:
                    raise ProtocolError("", "values items should be a list")
        else:
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
            raise ValueError("Unable to decode element of dict at %d %r" % (j[0], data[:max]))

    cdef int _decode_values(self, char* data, int *i, int max) nogil except -1:
        cdef int j[1]
        cdef int c = 0
        cdef int k = i[0] + 1
        cdef char** values
        if i[0] >= max:
            with gil:
                raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
        if not data[i[0]] == b'l':
            return False
        i[0]+=1
        while _decode_string(data, i, max, j):
            if (i[0]-j[0]) != 6:
                with gil:
                    raise ValueError("element of values are expected to be of length 6 and not %s" % (i[0]-j[0]))
            c+=1
        if i[0] >=  max or data[i[0]] != b'e':
            with gil:
                raise ValueError("End of values list not found %s >= %s found %s elements" % (i[0], max, c))
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
        cdef int k
        if data[i[0]] == b'd':
            i[0]+=1
            while data[i[0]] != b'e' and i[0] < max:
                k = i[0]
                if not self._decode_dict_elm(data, i, max):
                    with gil:
                        raise ValueError("fail to decode dict element %d %r" % (k, data[:max]))
        if data[i[0]] != b'e':
            with gil:
                raise ValueError("End of dict not found %s>=%d %r" % (i[0], max, data[:max]))
        else:
            i[0]+=1
            return True

    cdef int _decode(self, char* data, int *i, int max) nogil except -1:
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
        cdef int i = 0
        cdef int valid = False
        with nogil:
            if datalen > 0:
                valid = self._decode(data, &i, datalen)
                if valid:
                    self.encoded_len = self._encode_len()
                    self.encoded = <char *> malloc(self.encoded_len * sizeof(char))
                    strncpy(self.encoded, data, self.encoded_len)
                    self.encoded_uptodate = True
                if not valid or not self.has_t or not self.has_y:
                    with gil:
                        if self.debug:
                            print("%r" % data)
                        if self.has_t:
                            raise ProtocolError(self._t[:self.t_len])
                        else:
                            raise ProtocolError("")
        return data[i:]
