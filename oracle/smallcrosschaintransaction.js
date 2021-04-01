"use strict";

const child_process = require("child_process");

const common = require("./common");

module.exports = async function (json_data, res) {
    try {
        console.log("received small crosschain transaction: ");
        let signature = json_data["params"]["signature"];
        let rawTx = json_data["params"]["rawTx"]

        let host = common.web3._provider.host

        var sendURL = 'curl -X POST --data' + " '" + '{"jsonrpc":"2.0","method":"eth_receivedSmallCrossTx","params":['  + '"' + signature  + '",' + '"' + rawTx + '"],"id":1}' + "' " + host + ' -H "content-type: application/json"'

        console.log("eth_receivedSmallCrossTx url=", sendURL)

        var child = child_process.exec(sendURL, function(err, stdout, stderr) {
            console.log("stdout", stdout);
        });


        res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": true});
        return;
    } catch (err) {
        console.log("smallcrosschaintx error==>", err);
        common.reterr(err, res);
        return;
    }

}
