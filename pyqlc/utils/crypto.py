import string
import struct
from base64 import b32encode, b32decode
from hashlib import blake2b
from . import ed25519_blake2b
from binascii import hexlify, unhexlify


maketrans = hasattr(bytes, 'maketrans') and bytes.maketrans or string.maketrans
B32_ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
QLC_ALPHABET = b"13456789abcdefghijkmnopqrstuwxyz"
QLC_ENCODE_TRANS = maketrans(B32_ALPHABET, QLC_ALPHABET)
QLC_DECODE_TRANS = maketrans(QLC_ALPHABET, B32_ALPHABET)

def address_checksum(address : bytes):
    """
    Returns the checksum in bytes for an address in bytes
    """
    address_bytes = address
    h = blake2b(digest_size=5)
    h.update(address_bytes)
    checksum = bytearray(h.digest())
    checksum.reverse()
    return checksum

def private_to_public_key(private_key : bytes):
    """
    Returns the public key for a private key
    :param private_key: private key (in bytes) to get public key for
    :type private_key: bytes
    """
    return ed25519_blake2b.publickey_unsafe(private_key)

def keypair_from_seed(seed : str, index : int = 0):
    """
    Generates a deterministic keypair from `seed` based on `index`
    :param seed: str value of seed
    :type seed: bytes
    :param index: offset from seed
    :type index: int
    :return: dict of the form: {
        'private': private_key
        'public': public_key
    }
    """
    seed = unhexlify(seed)
    h = blake2b(digest_size=32)
    h.update(seed + struct.pack(">L", index))
    priv_key = h.digest()
    pub_key = private_to_public_key(priv_key)
    return {'private': priv_key, 'public': pub_key}

def b32qlc_encode(value):
    """
    Encodes bytes to qlc encoding which uses the base32 algorithm
    with a custom alphabet: '13456789abcdefghijkmnopqrstuwxyz'
    :param value: the value to encode
    :type: bytes
    :return: encoded value
    :rtype: bytes
    >>> b32qlc_encode(b'deadbeef')
    b'ejkp4s54eokpe==='
    """
    return b32encode(value).translate(QLC_ENCODE_TRANS)

def b32qlc_decode(value):
    """
    Decodes a value in qlc encoding to bytes using base32 algorithm
    with a custom alphabet: '13456789abcdefghijkmnopqrstuwxyz'
    :param value: the value to decode
    :type: bytes
    :return: decoded value
    :rtype: bytes
    >>> b32qlc_decode(b'fxop4ya=')
    b'okay'
    """
    return b32decode(value.translate(QLC_DECODE_TRANS))

def verify_signature(message, signature, public_key):
    """
    Verifies `signature` is correct for a `message` signed with `public_key`
    :param message: message to check
    :type message: bytes
    :param signature: signature to check
    :type signature: bytes
    :param public_key: public_key to check
    :type public_key: bytes
    :return: True if valid, False otherwise
    :rtype: bool
    """

    try:
        ed25519_blake2b.checkvalid(signature, message, public_key)
    except ed25519_blake2b.SignatureMismatch:
        return False
    return True

#def __sign_message(message, private_key, public_key):
#    """
#    Signs a `message` using `private_key` and `public_key`
#    .. warning:: Not safe to use with secret keys or secret data. See module
#                 docstring.  This function should be used for testing only.
#    :param message: the message to sign
#    :type message: bytes
#    :param private_key: private key used to sign message
#    :type private_key: bytes
#    :return: the signature of the signed message
#    :rtype: bytes
#    """
#    return ed25519_blake2.signature_unsafe(message, private_key, public_key)