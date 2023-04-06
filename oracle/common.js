"use strict";

const Web3 = require("web3");
const web3 = new Web3("http://127.0.0.1:20636");
const ctrt = require("./ctrt");
const pledgeBillContract = require("./pledgeBillContract");


web3.extend({
    methods: [{
        name: 'getFailedRechargeTxs',
        call: 'eth_getFailedRechargeTxs',
        params: 1,
    },
    {
            name: 'getFailedRechargeTxByHash',
            call: 'eth_getFailedRechargeTxByHash',
            params: 1,
    },
    {
        name: 'sendInvalidWithdrawTransaction',
        call: 'eth_sendInvalidWithdrawTransaction',
        params: 2,
    },
    {
        name: 'receivedSmallCrossTx',
        call: 'eth_receivedSmallCrossTx',
        params: 2,
    },
    {
        name: 'onSmallCrossTxSuccess',
        call: 'eth_onSmallCrossTxSuccess',
        params: 1,
    },
    {
        name: 'getFrozenAccounts',
        call: 'eth_getFrozenAccounts',
        params: 0,
    }
    ]
});
const contract = new web3.eth.Contract(ctrt.abi);
const pledgeBill = new web3.eth.Contract(pledgeBillContract.abi)
console.log(JSON.stringify(process.env.env));
switch (process.env.env) {
    case "rinkeby":
        console.log("0x491bC043672B9286fA02FA7e0d6A3E5A0384A31A");
        contract.options.address = "0x491bC043672B9286fA02FA7e0d6A3E5A0384A31A";
        pledgeBill.options.address = "0x6E543Bb812D88eeDD07E4217cCF9635Da2a00Ddb"
        break;
    case "testnet":
        console.log("0x491bC043672B9286fA02FA7e0d6A3E5A0384A31A");
        contract.options.address = "0x491bC043672B9286fA02FA7e0d6A3E5A0384A31A";
        pledgeBill.options.address = "0x95c87f9c2381d43fc7019A2F7A2EA1dd8CA47230"
        break;
    case "mainnet":
        console.log("0xC445f9487bF570fF508eA9Ac320b59730e81e503");
        contract.options.address = "0xC445f9487bF570fF508eA9Ac320b59730e81e503";
        pledgeBill.options.address = "0x06D49BB1F338420E1d8577829C079DCB4cb5eF25"
        break;
    default:
        console.log("config address");
        contract.options.address = ctrt.address;
        pledgeBill.options.address = pledgeBillContract.address
        console.log("pledgeBill.options.address", pledgeBill.options.address);
}
const payloadReceived = {name: null, inputs: null, signature: null};
const blackAdr = "0x0000000000000000000000000000000000000000";
const zeroHash64 = "0x0000000000000000000000000000000000000000000000000000000000000000";
const latest = "latest";

for (const event of ctrt.abi) {
    if (event.name === "PayloadReceived" && event.type === "event") {
        payloadReceived.name = event.name;
        payloadReceived.inputs = event.inputs;
        payloadReceived.signature = event.signature;
    }
}

const pledgeBillBurnEvent = pledgeBillContract.abi[0]

module.exports = {
    web3: web3,
    contract: contract,
    payloadReceived: payloadReceived,
    pledgeBillBurnEvent:pledgeBillBurnEvent,
    pledgeBillContract:pledgeBill,
    blackAdr: blackAdr,
    latest: latest,
    zeroHash64: zeroHash64,
    reterr: function(err, res) {
        console.log("Error Encountered: ");
        console.log(err.toString());
        console.log("============================================================");
        res.json({"error": err.toString(), "id": null, "jsonrpc": "2.0", "result": null});
        return;
    },
    retnum: function toNonExponential(num) {
        let value = num.toString()
        let numList = value.split(".")
        let returnValue = value
        if (numList.length > 1) {
            let precisionStr = numList[1]
            if (precisionStr.length > 8) {
                let b = precisionStr.substr(precisionStr.lastIndexOf(".") + 1,8)
                returnValue = numList[0] + "." + b
            }
        }
        return returnValue
    }
};
