from . import client

class Miner:
    def __init__(self, URI):
        self.URI = URI

    def getAvailRewardInfo(self, coinbase : str) -> dict:
        """
        Return miner available reward info by coinbase address. Client should call miner reward contract when needCallReward in returns is true 

        Parameters
        ----------
        coinbase : str
            miner address
        """
        return client.Client(self.URI).post("miner_getAvailRewardInfo", [coinbase])

    def getRewardSendBlock(
        self,
        coinbase : str,
        beneficial : str,
        startHeight : int,
        endHeight : int,
        rewardBlocks : int,
        **kwargs) -> dict:
        """
        Return contract send block by reward parameters

        Parameters
        ----------
        coinbase : str
        beneficial : str
        startHeight : int
        endHeight : int
        rewardBlocks : int

        e.g.
        ----
        {
			"coinbase": "qlc_1szuejgo9nxdre1uwpsxni4fg7p8kx7micbsdtpnchmc3cfk4wt1i37uncmy",
			"beneficial": "qlc_1szuejgo9nxdre1uwpsxni4fg7p8kx7micbsdtpnchmc3cfk4wt1i37uncmy",
			"startHeight": 120,
			"endHeight": 239,
			"rewardBlocks": 42
        }
        """ 

        params = {
            "coinbase" : coinbase,
            "beneficial" : beneficial,
            "startHeight" : startHeight,
            "endHeight" : endHeight,
            "rewardBlocks" : rewardBlocks     
        }
        
        for k, _ in kwargs.items():
            params["coinbase"] = k["coinbase"]
            params["beneficial"] = k["beneficial"]
            params["startHeight"] = k["startHeight"]
            params["endHeight"] = k["endHeight"]
            params["rewardBlocks"] = k["rewardBlocks"] 
        
        return client.Client(self.URI).post("miner_getRewardSendBlock", [params])


    def getRewardRecvBlockBySendHash(self, sendHash : str) -> dict:
        """
        Return miner available reward info by coinbase address. Client should call miner reward contract when needCallReward in returns is true 

        Parameters
        ----------
        sendHash : str
            contract send block hash
        """
        return client.Client(self.URI).post("miner_getRewardRecvBlockBySendHash", [sendHash])

    def getRewardRecvBlock(
        self,
        address : str,
        balance : str,
        data : str,
        extra : str,
        link : str,
        message : str,
        network : str,
        oracle : str,
        povHeight : str,
        previous : str,
        representative : str,
        signature : str,
        storage : str,
        timestamp : str,
        token : str,
        Type : str,
        vote : str,
        work : str,
        **kwargs) -> dict:
        """
        Return contract reward block by contract send block

        Parameters
        ----------
        address : str
        balance : str
        data : str
        extra : str
        link : str
        message : str
        network : str
        oracle : str
        povHeight : int
        previous : str
        representative : str
        signature : str
        storage : str
        timestamp : int
        token : str
        type : str
        vote : str
        work : str

        e.g.
        ----
		{
			"address": "qlc_1szuejgo9nxdre1uwpsxni4fg7p8kx7micbsdtpnchmc3cfk4wt1i37uncmy",
			"balance":"19800000000000000",
			"data": "aXMKz2f7ZF1T06vDAb5bPaQE1xbGl0s4KTlerUU+agqbIXNAZ/tkXVPTq8MBvls9pATXFsaXSzgpOV6tRT5qCpshc0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACo=",
			"extra": "0000000000000000000000000000000000000000000000000000000000000000",
			"link": "0000000000000000000000000000000000000000000000000000000000000015",
			"message": "0000000000000000000000000000000000000000000000000000000000000000",
			"network":"0",
			"oracle":"0",
			"povHeight":1596,
			"previous": "e6363d535378796fdcdf635b58b9b2a54a579364fd8e5a814b0a5c9969854884",
			"representative": "qlc_1szuejgo9nxdre1uwpsxni4fg7p8kx7micbsdtpnchmc3cfk4wt1i37uncmy",
			"signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"storage":"0",
			"timestamp":1563434320,
			"token": "a7e8fa30c063e96a489a47bc43909505bd86735da4a109dca28be936118a8582",
			"type":"ContractSend",
			"vote":"100000000000000",
			"work":"0000000000000000"
		}
        """ 
        params = {  
		    "address": address,
		    "balance": balance,
		    "data": data,
		    "extra": extra,
		    "link": link,
		    "message": message,
		    "network": network,
		    "oracle": oracle,
		    "povHeight": povHeight,
		    "previous": previous,
		    "representative": representative,
		    "signature": signature,
		    "storage": storage,
		    "timestamp": timestamp,
		    "token": token,
		    "type": Type,
		    "vote": vote,
		    "work": work
        }

        for k, _ in kwargs.items():
            params["address"] = k["address"]
            params["balance"] = k["balance"]
            params["data"] = k["data"]
            params["extra"] = k["extra"]
            params["link"] = k["link"]
            params["message"] = k["message"]
            params["network"] = k["network"]
            params["oracle"] = k["oracle"]
            params["povHeight"] = k["povHeight"]
            params["previous"] = k["previous"]
            params["representative"] = k["representative"]
            params["signature"] = k["signature"]
            params["storage"] = k["storage"]
            params["timestamp"] = k["timestamp"]
            params["token"] = k["token"]
            params["type"] = k["type"]
            params["vote"] = k["vote"]
            params["work"] = k["work"]

        return client.Client(self.URI).post("miner_getRewardRecvBlock", [params])

    def getRewardHistory(self, coinbase : str) -> dict:
        """
        Return miner's contract reward history

        Parameters
        ----------
        coinbase : str
            miner's address
        """
        return client.Client(self.URI).post("miner_getRewardHistory", [coinbase])