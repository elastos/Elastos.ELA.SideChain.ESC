"use strict";

const common = require("./common");

module.exports = async function (json_data, res) {
    try {
        let height = json_data["params"]["height"];
        let failedTxs = await common.web3.getFailedRechargeTxs(height)
        console.log("failedTxs", failedTxs)
        res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": failedTxs});
        return;
    } catch (err) {
        console.log("failed deposit transaction error==>", err);
        common.reterr(err, res);
        return;
    }
}