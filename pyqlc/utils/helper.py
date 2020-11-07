import sys

def size_in_bytes(object):
    size = sys.getsizeof(object)
    return size

def getBlock(
    address : str,
    balance : str,
    data : str,
    extra : str,
    link : str,
    message : str,
    network : str,
    oracle : str,
    povHeight : int,
    previous : str,
    representative : str,
    signature : str,
    storage : str,
    timestamp : int,
    token : str,
    type : str,
    vote : str,
    work : str,
    **kwargs) -> dict:
    
    block = {  
	    "address": str(address),
	    "balance": str(balance),
	    "data": str(data),
	    "extra": str(extra),
	    "link": str(link),
	    "message": str(message),
	    "network": str(network),
	    "oracle": str(oracle),
	    "povHeight": int(povHeight),
	    "previous": str(previous),
	    "representative": str(representative),
	    "signature": str(signature),
	    "storage": str(storage),
	    "timestamp": int(timestamp),
	    "token": str(token),
	    "type": str(type),
	    "vote": str(vote),
	    "work": str(work)
    }

    for k, _ in kwargs.items():
        block["address"] = k["address"]
        block["balance"] = k["balance"]
        block["data"] = k["data"]
        block["extra"] = k["extra"]
        block["link"] = k["link"]
        block["message"] = k["message"]
        block["network"] = k["network"]
        block["oracle"] = k["oracle"]
        block["povHeight"] = k["povHeight"]
        block["previous"] = k["previous"]
        block["representative"] = k["representative"]
        block["signature"] = k["signature"]
        block["storage"] = k["storage"]
        block["timestamp"] = k["timestamp"]
        block["token"] = k["token"]
        block["type"] = k["type"]
        block["vote"] = k["vote"]
        block["work"] = k["work"]

    return block
