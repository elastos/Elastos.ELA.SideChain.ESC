"use strict";

const child_process = require("child_process");

const common = require("./common");

module.exports = async function (json_data, res) {
    try {
        console.log("received small crosschain transaction: ");
        let signature = json_data["params"]["signature"];
        let rawTx = json_data["params"]["rawTx"]
        let mctxhash = json_data["params"]["txHash"];
        if (mctxhash.indexOf("0x") !== 0) mctxhash = "0x" + mctxhash;

        let txprocessed = await common.web3.eth.getStorageAt(common.blackAdr, mctxhash, common.latest)
        if (txprocessed != common.zeroHash64) {
            console.log("allready accept txid", mctxhash)
            common.web3.onSmallCrossTxSuccess(mctxhash)
            res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": true});
            return;
        }

        await common.web3.receivedSmallCrossTx(signature, rawTx);
        res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": false});
        return;
    } catch (err) {
        common.reterr(err, res);
        return;
    }

}
