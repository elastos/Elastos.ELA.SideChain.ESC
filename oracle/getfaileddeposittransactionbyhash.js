"use strict";

const common = require("./common");
const child_process = require("child_process");

module.exports = async function (json_data, res) {
    try {
        let hash = json_data["params"]["hash"];
        let host = common.web3._provider.host
        let failedTx = ""
        var sendURL = 'curl -X POST --data' + " '" + '{"jsonrpc":"2.0","method":"eth_getFailedRechargeTxByHash","params":['  + '"' + hash  + '"],"id":1}' + "' " + host + ' -H "content-type: application/json"'
        console.log("eth_getFailedRechargeTxByHash url=", sendURL);
        await child_process.exec(sendURL, function(err, stdout, stderr) {
            let jsonData = JSON.parse(stdout)
            if (jsonData["error"] != null) {
                console.log("stdout", stdout);
                res.json({"error": null, "id": null, "jsonrpc": "2.0", "result":failedTx});
                return
            }
            console.log("jsonData", jsonData);
            failedTx=jsonData["result"];
            res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": failedTx});
        });
        return;
    } catch (err) {
        console.log("failed deposit transaction by hash error==>", err);
        common.reterr(err, res);
        return;
    }
}