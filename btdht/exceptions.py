class BucketFull(Exception):
    """
        Raised then trying to add a node to a :class:`Bucket<btdht.dht.Bucket>` that
        already contains :class:`Bucket.max_size<btdht.dht.Bucket.max_size>` elements.
    """
    pass

class BucketNotFull(Exception):
    """
        Raises then trying to split a split a :class:`Bucket<btdht.dht.Bucket>` that
        contains less than :class:`Bucket.max_size<btdht.dht.Bucket.max_size>` elements.
    """
    pass

class NoTokenError(Exception):
    """
        Raised then trying to annonce to a node we download an info_hash
        using :meth:`Node.announce_peer<btdht.dht.Node.announce_peer>` but we do not known any valid
        token. The error should always be catch and never seen by btdht users.
    """
    pass

class FailToStop(Exception):
    """Raises then we are tying to stop threads but failing at it"""
    pass

class TransactionIdUnknown(Exception):
    """Raised then receiving a response with an unknown ``t`` key"""
    pass

class MissingT(ValueError):
    """Raised while decoding of a dht message if that message of no key ``t``"""
    pass

class DecodeError(ValueError):
    """Raised while decoding a dht message"""
    pass

class BcodeError(Exception):
    """Raised by :func:`btdht.utils.bdecode` and :func:`btdht.utils.bencode` functions"""
    pass

class NotFound(Exception):
    """
        Raised when trying to get a node that do not exists from a :class:`Bucket<btdht.dht.Bucket>`
    """
    pass

