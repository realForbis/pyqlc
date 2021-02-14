# qlc-python-SDK

## Examples

### Create 3 random accounts
```python
from pyqlc.client import Client

def example():
	qlc = Client("http://127.0.0.1:9735")
	
	accounts = qlc.Account.newAccounts(3)

	for idx, addr in enumerate(accounts):
		print(f"{idx} ==> {addr}")

example()
"""
Output:

0 ==> {
    'address': 'qlc_1i5emtz19w75cnzpcm3gn96smp4se8s5cn8potw7si456tapz3npemjwwami',
    'privKey': b'cc8f2fb68202526ebab7a968fa81883c29785dc4599e46126f422b11f4402f3f406c9ebe03f0a3553f654c2ea1c999d85961b23550d6aeb85cc04326916f8696',
    'pubKey': b'406c9ebe03f0a3553f654c2ea1c999d85961b23550d6aeb85cc04326916f8696',
    'seed': '7e6cbeb02e3247ae82fd0f0eb5030ed857c516f5fa4bba513ede65dffa863d31'
    }
1 ==> {
    'address': 'qlc_3duidxc7cuizuoj8gx7crpykbibweqe9kpc9fsgohz6arfzowoki5ip7ddcw',
    'privKey': b'ba9f8339fc6b0950d5b3afa3aaaad1518d32d098aa3f2715e1247acf45a72569af705f54556e1fdd626774aac5bd24c13c65d87959476e5d57fc88c37f5e5650',
    'pubKey': b'af705f54556e1fdd626774aac5bd24c13c65d87959476e5d57fc88c37f5e5650',
    'seed': '256d61e9a26f1209e62daff747e2caa959211324c1ffee04df3bbdeaa5c197d4'
    }
2 ==> {
    'address': 'qlc_3pe9cd67cbhtjgh67g79qdi9o8poto9jnyznsk5ofb6u8xaf1urnytsno345',
    'privKey': b'5e8d3b00cef26f73660144287dbe0c705825ba780fcba1828d41dd423cd5dc7ad98752c85525fa8b9e42b8a7bae07a9ad5d54f1a7bf4cc8756a49b3750d06f14',
    'pubKey': b'd98752c85525fa8b9e42b8a7bae07a9ad5d54f1a7bf4cc8756a49b3750d06f14',
    'seed': 'd20d72e3fb07b4936d8eee49cb23cf4e796fca566af07eaaf6c8578ab257103b'
    }
"""
```

### Sending transaction
```python
from pyqlc.client import Client
import json

def main():
    qlc = Client("https://rpc.qlcchain.online/")

    Alice = {
        "address" : "qlc_3xc5fbrqck6mrxrrx7hjnqf6jgyqsnkeg39k5mjw44m8aj3f1zdfh7cw8kzz",
        "private_key" : "8e6bc788bbeae46f26315dd91bbbc6891278bf3bfb228aa901b39f3f1c169efbf5436a71754893c7718e95f1a5da48bbd7cd24c704f21ce3c10a664332d07d6d"
    }

    seed = qlc.Account.newSeed(local= True)
    new_account = qlc.Account.create(seed= seed, index= 0, local= True)
    Bob = {
        "address" : new_account["address"]
    }

    send_block = qlc.Ledger.generateSendBlock(From= Alice["address"], to= Bob["address"], tokenName= "QGAS", amount=1, privKey= Alice["private_key"])
    print(f"block = {json.dumps(send_block, indent= 4)}")

    _hash = qlc.Ledger.process(**send_block)
    print(f"hash = {_hash}")

main()
"""
Output:

block = {
    "type": "Send",
    "token": "ea842234e4dc5b17c33b35f99b5b86111a3af0bd8e4a8822602b866711de6d81",
    "address": "qlc_3xc5fbrqck6mrxrrx7hjnqf6jgyqsnkeg39k5mjw44m8aj3f1zdfh7cw8kfz",
    "balance": "346854",
    "vote": "0",
    "network": "0",
    "storage": "0",
    "oracle": "0",
    "previous": "738642163581ddab31e171813abd1301bb7d14c7f470ca91f65717710c45a464",
    "link": "42d2f239db3798b1f60b182e72790e71fe805e0eb62eef7a2e06646d71cfc695",
    "message": "0000000000000000000000000000000000000000000000000000000000000000",
    "povHeight": 514397,
    "timestamp": 1613280327,
    "extra": "0000000000000000000000000000000000000000000000000000000000000000",
    "representative": "qlc_1111111111111111111111111111111111111111111111111111hifc8npp",
    "work": "0000000000a70611",
    "signature": "f01b8100ab050bd8efed9585f88ae4777c86fd050053b43a3bca2ec5e04c5cefdc12b108eaec792bb70ebe546a7dbdf6f63ca34a4eb6cf95b93259cae6cc970b"
}
hash = 6014521eb956b589013540174951ba690cde4f2d98b0fbc291f0f94ac1bbbb87
"""
```
## Requirements
```shell
$ pip3 install -r requirements.txt
```