import secrets
from .utils import crypto
import binascii
from . import client

ADDRESSPREFIX = "qlc_"
ADDRESSLEN = 60
ADDRESSPREFIXLEN = len(ADDRESSPREFIX)
HEXADDRESSLENGHT = ADDRESSPREFIXLEN + ADDRESSLEN
PUBLICKEYSIZEINBYTES = 32

class Account:
    def __init__(self, URI):
        self.URI = URI

    def create(self, seed : str = None, index : int = 0, local : bool = True) -> dict:
        """
        Create a new account by seed and index
        
        Parameters
        ----------
        seed : str
        index : uint32 
            index for account, if not set, default value is 0
        local : bool
            if local is set to `True`, account will be created localy

        Returns
        ----------
        address, privKey, pubKey

        e.g.
        ----
        {
            'address': 'qlc_3wkft3s69t59c7rbjyozam6j5ib7ooug7sogsfg5abwaf1qiprgxpap6suiu', 
            'privKey': b'54e704e605641da0ffee6898c1e336e88b0437e2399554675e4a6710f68ed6c2f24dd07243e867517098fabf44c911c125ad76e2e6aecb5c342788682f0b61dd',
            'pubKey': b'f24dd07243e867517098fabf44c911c125ad76e2e6aecb5c342788682f0b61dd'
        }
        """
        if seed is None:
            if local:
                seed = self.newSeed(local = True)       
            else:
                seed = self.newSeed(local = False)

        if local:
            pair = crypto.keypair_from_seed(seed, index=index)
            account = {
                'address': self.forPublicKey(public_key = pair['public'], local = True),
                'privKey': binascii.hexlify(pair['private']+pair['public']),
                'pubKey': binascii.hexlify(pair['public']),
            }
            return account
  
        else:
            params = [seed, index]
            account = client.Client(self.URI).post("account_create", params)
            account["address"] = self.forPublicKey(account["pubKey"], local = False)
            return account

    def newSeed(self, local : bool = True) -> str:
        """
        Create a new seed randomly

        Parameters
        ----------
        local : bool
            if local is set to `True`, seed will be generated localy

        Returns
        ----------
        seed : str
        """
        if local:
            return secrets.token_hex(32)
        else:
            return client.Client(self.URI).post("account_newSeed")

    def newAccounts(self, num : int = 10, local : bool = True) -> list:
        """
        Create new accounts randomly

        Parameters
        ----------
        num : uint32 
            number of accounts, default is 10
        local : bool
            if local is set to `True`, accounts will be created localy

        Returns
        ----------
        list of accounts
        """
        if local:
            accounts = []
            for _ in range(num):
                seed = self.newSeed(local=True)
                account = self.create(seed = seed, local = True)
                account["seed"] = seed
                accounts.append(account)
            return accounts
        else:
            return client.Client(self.URI).post("account_newAccounts", [num])

    def forPublicKey(self, public_key : str, local : bool = True) -> str:
        """
        Return account address by public key

        Parameters
        ----------
        pub_key : str
            public key
        local : bool
            if local is set to `True`, public key will be converted localy
        """

        if local:
            if type(public_key) != bytes:
                public_key = binascii.unhexlify(public_key)
                if not len(public_key) == PUBLICKEYSIZEINBYTES:
                    raise ValueError('public key must be 32 chars')
            padded = b'000' + public_key
            address = crypto.b32qlc_encode(padded)[4:]
            checksum = crypto.b32qlc_encode(crypto.address_checksum(public_key))
            return ADDRESSPREFIX + address.decode('ascii') + checksum.decode('ascii')
        else:
            return client.Client(self.URI).post("account_forPublicKey", [public_key])
        
    def publicKey(self, address : str, local : bool = True) -> bytes:
        """
        return public key for account address

        Parameters
        ----------
        address : bytes 
            account address
        local : bool
            if local is set to `True`, address will be converted localy
        """
        if local:
            address = bytearray(address, 'ascii')

            if not address.startswith(b"qlc_"):
                raise ValueError(f'address does not start with qlc_: {address}')

            if len(address) != HEXADDRESSLENGHT:
                raise ValueError(f"address must be 64 chars long: {address}")

            address = bytes(address)
            key_b32qlc = b'1111' + address[4:56]
            key_bytes = crypto.b32qlc_decode(key_b32qlc)[3:]
            checksum = address[56:]

            if crypto.b32qlc_encode(crypto.address_checksum(key_bytes)) != checksum:
                raise ValueError(f"invalid address, invalid checksum: {address}")

            return binascii.hexlify(key_bytes)
        else:
            pk = client.Client(self.URI).post("account_publicKey", [address])
            return pk.encode()

    def validate(self, address : str, local : bool = True) -> bool:
        """
        return whether the address is valid or not

        Parameters
        ----------
        address : str 
            account address
        local : bool
            if local is set to `True`, address will be checked localy
        """
        if local:
            try:
                self.publicKey(address, local = True)
                return True
            except:
                return False
        else:
            return client.Client(self.URI).post("account_validate", [address])
