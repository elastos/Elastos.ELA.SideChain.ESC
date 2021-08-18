"use strict";

const common = require("./common");
const child_process = require("child_process");

module.exports = async function (json_data, res) {
    try {
        let hash = json_data["params"]["hash"];
        let failedTx = await common.web3.getFailedRechargeTxByHash(hash)
        res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": failedTx});
        return;
    } catch (err) {
        console.log("failed deposit transaction by hash error==>", err);
        common.reterr(err, res);
        return;
    }
}