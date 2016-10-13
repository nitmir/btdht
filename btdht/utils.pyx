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
from functools import total_ordering

from libc.stdlib cimport atoi, malloc, free
from libc.string cimport strlen, strncmp, strcmp, strncpy, strcpy
from cython.parallel import prange
from .krcp cimport _decode_string, _decode_int as _decode_long
cdef extern from "ctype.h":
    int isdigit(int c)

cdef char BYTE_TO_BIT[256][8]
# fill BYTE_TO_BIT array
def __init():
    for i in range(256):
        s = "{0:08b}".format(i).encode("ascii")
        strncpy(BYTE_TO_BIT[i], <char *>s, 8)
__init()
del __init

cdef char _longid_to_char(char* id) nogil:
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
    cdef int i
    cdef char* id
    if size/8*8 != size:
        with gil:
            raise ValueError("size must be a multiple of 8")
    id = <char*>malloc((size / 8) * sizeof(char))
    i=0
    while i < size:
        id[i/8] = _longid_to_char(longid + i)
        i+=8
    return id

cdef char* _id_to_longid(char* id, int size=20) nogil:
    global BYTE_TO_BIT
    cdef char* ret = <char*>malloc((size * 8) * sizeof(char))
    cdef int i = 0   
    while i < size:
        strncpy(ret + (i*8), BYTE_TO_BIT[<unsigned char>id[i]], 8)
        i+=1
    return ret

def id_to_longid(char* id, int l=20):
    """
    convert a random char* to a unicode string of 1 and 0
    example : "\0" -> "00000000"
    """
    #cdef int l = len(id)
    with nogil:
        ret = _id_to_longid(id, l)
    u = (ret[:l*8]).decode('ascii')
    free(ret)
    return u

def nbit(s, n):
    """Renvois la valeur du nième bit de la chaine s"""
    c=str(s)[n/8]
    return int(format(ord(c), '08b')[n % 8])

def nflip(s, n):
    """Renvois la chaine s dont la valeur du nième bit a été retourné"""
    bit = [0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010, 0b00000001]
    return s[:n/8]  + chr(ord(s[n/8]) ^ bit[n % 8]) + s[n/8+1:]

def nset(s, n , i):
    bit1 = [0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010, 0b00000001]
    bit0 = [0b01111111, 0b10111111, 0b11011111, 0b11101111, 0b11110111, 0b11111011, 0b11111101, 0b11111110]
    if i == 1:
        return s[:n/8]  + chr(ord(s[n/8]) | bit1[n % 8]) + s[n/8+1:]
    elif i == 0:
        return s[:n/8]  + chr(ord(s[n/8]) & bit0[n % 8]) + s[n/8+1:]
    else:
        raise ValueError("i doit être 0 ou 1")
    
class BcodeError(Exception):
    pass

def enumerate_ids(size, id):
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

@total_ordering
class ID(object):

    @classmethod
    def to_bytes(cls, id):
        try:
            return id.value
        except AttributeError:
            return id

    @staticmethod
    def __generate():
        return os.urandom(20)

    def __init__(self, id=None):
        if id is None:
            self.value = self.__generate()
        else:
            self.value = self.to_bytes(id)

    def encode(self, c):
        return self.value.encode(c)

    def startswith(self, s):
        return self.value.startswith(s)

    def __getitem__(self, i):
        return self.value[i]

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value.encode("hex")

    def __eq__(self, other):    
        if isinstance(other, ID):
            return self.value == other.value
        elif isinstance(other, str):
            return self.value == other
        else:
            return False

    def __lt__(self, other):
        if isinstance(other, ID):
            return self.value < other.value
        elif isinstance(other, str):
            return self.value < other
        else:
            raise TypeError("unsupported operand type(s) for <: 'ID' and '%s'" % type(other).__name__)
            
    def __len__(self):
        return len(self.value)

    def __xor__(self, other):
        if isinstance(other, ID):
            return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(self.value, other.value))
        elif isinstance(other, str):
            return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(self.value, other))
        else:
            raise TypeError("unsupported operand type(s) for ^: 'ID' and '%s'" % type(other).__name__)

    def __rxor__(self, other):
        return self.__xor__(other)

    def __hash__(self):
        return hash(self.value)

def bencode(obj):
    try:
        return _bencode(obj)
    except:
        print("%r" % obj)
        raise
def _bencode(obj):
    
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
        raise EnvironmentError("Can only encode int, str, list or dict, not %s" % type(obj).__name__)

def bdecode(s):
    return _bdecode(s)[0]

cdef _decode_int(char* data, int *i, int max):
    """decode arbitrary long integer"""
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
                         raise ValueError("%s > %s : %r" % (i[0], max, data[:max]))
            else:
                with gil:
                    raise ValueError("%s != e at %s %r" % (data[j], j, data[:max]))
        else:
            with gil:
                return False

cdef _decode_list(char* data, int* i, int max):
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
                raise ValueError("??? %s" % data[i[0]])
    i[0]+=1
    return l

cdef _decode_dict(char* data, int* i, int max):
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
                raise ValueError("??? key must by string")
            if data[i[0]] == b'e':
                raise ValueError("??? key without value")
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
                raise ValueError("??? dict value%s" % data[i[0]])
    i[0]+=1
    return d

cdef _decode(char* data, int max):
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
            raise ValueError("??? dict value%s" % data[i[0]])
    except ValueError as e:
        raise BcodeError(str(e))

def _bdecode(s):
    return _decode(s, len(s))
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

