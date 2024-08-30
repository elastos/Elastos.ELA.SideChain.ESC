"use strict";

const common = require("./common");

module.exports = async function (json_data, res) {
    try {
        console.log("Getting PledgeBill Burn Logs At Block Height: ");
        let blkheight = json_data["params"]["height"];
        console.log("blkheight", blkheight);
        console.log("============================================================" ,common.pledgeBillContract.options.address);
        let logs = null;
        if (parseInt(blkheight) > 7) {
            logs = await common.pledgeBillContract.getPastEvents(common.pledgeBillBurnEvent.name, {
                fromBlock: parseInt(blkheight) - 6,
                toBlock: parseInt(blkheight) - 6
            });
        }
        let result = new Array();
        if (logs != null) {
            for (const log of logs) {
                if (log["address"] !== common.pledgeBillContract.options.address) {
                    continue;
                }
                console.log("log", log)
                let tkID = log["returnValues"]["tokenId"];
                let tkIDHex = BigInt(tkID).toString(16);
                let idSize = tkIDHex.length;
                for (let i = 0; i < 64 - idSize; i++) {
                    tkIDHex = "0" + tkIDHex;
                }
                result.push({
                    "tokenID": tkIDHex,
                    "saddress": log["returnValues"]["elaAddress"]
                });
            }
        }
        console.log("result", result);
        res.json({"result": result, "id": null, "error": null, "jsonrpc": "2.0"});
        console.log("============================================================\n\n\n\n");
        return;
    } catch (err) {
        common.reterr(err, res);
        return;
    }
}