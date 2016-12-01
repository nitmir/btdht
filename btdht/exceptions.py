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

class MissingT(ValueError):
    pass

class DecodeError(ValueError):
    pass

class BcodeError(Exception):
    pass

class NotFound(Exception):
    pass

