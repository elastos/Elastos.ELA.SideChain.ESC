"use strict";

const common = require("./common");

module.exports = async function (json_data, res) {
    try {
        let txs = json_data["params"]["txs"];
        console.log("received process invalied withdraw tx", txs)
        let i = 0;
        let list = new Array();
        for (i = 0; i < txs.length; i++) {
            let tx = txs[i]
            if (tx.indexOf("0x") !== 0) {
                tx = "0x" + txs[i];
            }
            let txprocessed = await common.web3.eth.getStorageAt(common.blackAdr, tx, common.latest)
            if (txprocessed != common.zeroHash64) {
                list.push(txs[i])
            }
        }
        console.log("all ready processed txs", list)
        res.json({"error": null, "id": null, "jsonrpc": "2.0", "result": list});
        return;
    } catch (err) {
        console.log("processed invalid withdraw transaction error==>", err);
        common.reterr(err, res);
        return;
    }
}