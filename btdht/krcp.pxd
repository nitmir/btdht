cdef long _decode_int(char* data, int *i, int max, long long *myint) nogil except -1
cdef int _decode_string(char* data, int* i, int max, int* j) nogil except -1
cdef class BMessage:
    cdef char* _y
    cdef int has_y
    cdef int y_len
    cdef char* _t
    cdef int has_t
    cdef int t_len
    cdef char* _q
    cdef int has_q
    cdef int q_len
    cdef char* _v
    cdef int has_v
    cdef int v_len
    cdef int r
    cdef int a
    cdef int e
    cdef int _errno
    cdef char* _errmsg
    cdef int errmsg_len
    cdef char* id
    cdef int has_id
    cdef char* target
    cdef int has_target
    cdef char* info_hash
    cdef int has_info_hash
    cdef int implied_port
    cdef int has_implied_port
    cdef int port
    cdef int has_port
    cdef char* token
    cdef int has_token
    cdef int token_len
    cdef char* nodes
    cdef int has_nodes
    cdef int nodes_len
    cdef char** values
    cdef int values_nb
    cdef int has_values
    cdef char* encoded
    cdef int encoded_len
    cdef int encoded_uptodate
    cdef int debug
    cdef unicode addr_addr_3
    cdef bytes addr_addr_2
    cdef int addr_port
    cdef int failed
    cdef char* failed_msg

    cdef int set_r(self, int value) nogil
    cdef int set_a(self, int value) nogil
    cdef int set_e(self, int value) nogil
    cdef int set_t(self, char* value, int size) nogil
    cdef void del_t(self) nogil
    cdef int set_v(self, char* value, int size) nogil
    cdef void del_v(self) nogil
    cdef int set_y(self, char* value, int size) nogil
    cdef void del_y(self) nogil
    cdef int set_q(self, char* value, int size) nogil
    cdef void del_q(self) nogil
    cdef int set_id(self, char* value, int size) nogil except -1
    cdef void del_id(self) nogil
    cdef int set_target(self, char* value, int size) nogil except -1
    cdef void del_target(self) nogil
    cdef int set_info_hash(self, char* value, int size) nogil except -1
    cdef void del_info_hash(self) nogil
    cdef void del_implied_port(self) nogil
    cdef int set_implied_port(self, int value) nogil
    cdef int set_port(self, int value) nogil
    cdef void del_port(self) nogil
    cdef int set_token(self, char* value, int size) nogil
    cdef void del_token(self) nogil
    cdef int set_nodes(self, char* value, int size) nogil
    cdef int del_nodes(self) nogil
    cdef int set_values(self, char** values, int nb) nogil
    cdef void del_values(self) nogil
    cdef int set_errmsg(self, char* value, int size) nogil
    cdef void del_errmsg(self) nogil
    cdef int set_errno(self, int value) nogil
    cdef void del_encoded(self) nogil

    cdef int _encode_values(self, char* data, int* i, int max) nogil

    cdef int _encode_secondary_dict(self, char* data, int* i, int max) nogil

    cdef int _encode_error(self, char* data, int* i, int max) nogil

    cdef int _encode_main_dict(self, char* data, int* i, int max) nogil

    cdef int _encode(self) nogil

    cdef int _encode_len(self) nogil

    cdef int _decode_error(self, char* data, int* i, int max) nogil except -1

    cdef int _decode_dict_elm(self, char* data, int* i, int max) nogil except -1

    cdef int _decode_values(self, char* data, int *i, int max) nogil except -1

    cdef int _decode_dict(self, char* data, int *i, int max) nogil except -1

    cdef int _decode(self, char* data, int *i, int max) nogil except -1
