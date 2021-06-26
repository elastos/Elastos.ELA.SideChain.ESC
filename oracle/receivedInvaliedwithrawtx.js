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
        let host = common.web3._provider.host;

        let txprocessed = await common.web3.eth.getStorageAt(common.blackAdr, tx, common.latest)
        if (txprocessed != common.zeroHash64) {
            console.log("Failed Withdraw Trasaction Hash already processed: " + txprocessed);
            console.log("============================================================");
            res.json({"error": null, "id": null, "jsonrpc": "2.0", "result":true});
            return;
        }

        var sendURL = 'curl -X POST --data' + " '" + '{"jsonrpc":"2.0","method":"eth_sendInvalidWithdrawTransaction","params":['  + '"' + signature  + '",' + '"' + failedTx + '"],"id":1}' + "' " + host + ' -H "content-type: application/json"'

        console.log("eth_sendInvalidWithdrawTransaction url=", sendURL);
        await child_process.exec(sendURL, function(err, stdout, stderr) {
            let jsonData = JSON.parse(stdout)
            if (jsonData["error"] != null) {
                console.log("stdout", stdout);
                res.json({"error": null, "id": null, "jsonrpc": "2.0", "result":false});
                return
            }
            console.log("jsonData", jsonData);
            failedTx=jsonData["result"];
            res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": false});
        });
        return;
    } catch (err) {
        console.log("failed withdraw transaction by hash error==>", err);
        common.reterr(err, res);
        return;
    }
}