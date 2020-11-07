import sys

def size_in_bytes(object):
    size = sys.getsizeof(object)
    return size