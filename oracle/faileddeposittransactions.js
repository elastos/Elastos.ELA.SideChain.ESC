"use strict";

const common = require("./common");
const child_process = require("child_process");

module.exports = async function (json_data, res) {
    try {
        let height = json_data["params"]["height"];
        let host = common.web3._provider.host
        var sendURL = 'curl -X POST --data' + " '" + '{"jsonrpc":"2.0","method":"eth_getFailedRechargeTxs","params":[' + height +  '],"id":1}' + "' " + host + ' -H "content-type: application/json"'
        console.log("eth_getFailedRechargeTxs url=", sendURL)
        let failedTxs = new Array();
        await child_process.exec(sendURL, function(err, stdout, stderr) {
            let jsonData = JSON.parse(stdout)
            if (jsonData["error"] != null) {
                console.log("stdout", stdout);
                res.json({"error": null, "id": null, "jsonrpc": "2.0", "result":failedTxs});
                return
            }
            failedTxs = jsonData["result"]
            console.log("failedTxs", failedTxs);
            res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": failedTxs});
        });
        return;
    } catch (err) {
        console.log("failed deposit transaction error==>", err);
        common.reterr(err, res);
        return;
    }
}