"use strict";
const common = require("./common");
let list = [];
let additional = [];

async function isFrozeAccount(from) {
    try {
        list =  await common.web3.getFrozenAccounts();
    } catch (e) {
        list = [];
    }
    let accounts = additional.concat(list)
    console.log("frozen accounts", accounts)
    let fromAcc = common.web3.utils.toChecksumAddress(from);
    for (var i = 0; i < accounts.length; i++) {
        let acc = common.web3.utils.toChecksumAddress(accounts[i]);
        if (acc == fromAcc) {
            return true;
        }
    }
    return false;
}

module.exports = {
    isFrozeAccount
}