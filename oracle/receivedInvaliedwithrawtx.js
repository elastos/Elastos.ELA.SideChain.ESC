"use strict";

const common = require("./common");
const child_process = require("child_process");

module.exports = async function (json_data, res) {
    try {
        let signature = json_data["params"]["signature"];
        let failedTx = json_data["params"]["txHash"];
        let tx = failedTx;
        if (tx.indexOf("0x") !== 0) {
            tx = "0x" + failedTx;
        }
        let txprocessed = await common.web3.eth.getStorageAt(common.blackAdr, tx, common.latest)
        if (txprocessed != common.zeroHash64) {
            console.log("Failed Withdraw Trasaction Hash already processed: " + txprocessed);
            console.log("============================================================");
            res.json({"error": null, "id": null, "jsonrpc": "2.0", "result":true});
            return;
        }
        await common.web3.sendInvalidWithdrawTransaction(signature, failedTx)
        res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": false});
        return;
    } catch (err) {
        common.reterr(err, res);
        return;
    }
}