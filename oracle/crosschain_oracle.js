"use strict";

const express = require("express");

const common = require("./common");
const getBlkNum = require("./getblknum");
const sendrechargetransaction = require("./sendrechargetransaction");
const getTxInfo = require("./gettxinfo");
const getBlkLogs = require("./getblklogs");
const getExistTxs = require("./getexisttxs");
const GetIllegalEvidenceByHeight=require("./getillegalevidencebyheight");
const CheckIllegalEvidence=require("./checkillegalevidence");
const Smallcrosschaintransaction=require("./smallcrosschaintransaction");
const FailedDepositTransactions=require("./faileddeposittransactions");
const GetFailedDepositTxByHash=require("./getfaileddeposittransactionbyhash");
const FailedWithdrawTxByHash=require("./receivedInvaliedwithrawtx");
const ProcessedFailedWithdrawTxs=require("./processedinvalidwithdrawtx");
const GetPledgeBillBurnLogsByHeight=require("./getPledgeBillBurnLogsByHeight")

const app = express();

var bodyParser = require('body-parser');
app.use(bodyParser.json({limit: '150mb'}));

app.use(express.json());

app.post("/", async function(req, res) {
    try {
        let json_data = req.body;
        console.log("JSON Data Received: ");
        console.log(json_data);
        console.log("============================================================");
        if (json_data["method"] === "getblockcount") {
            await getBlkNum(res);
            return;
        }
        if (json_data["method"] === "sendrechargetransaction") {
            await sendrechargetransaction(json_data, res);
            return;
        }
        if (json_data["method"] === "getwithdrawtransaction") {
            await getTxInfo(json_data, res);
            return;
        }
        if (json_data["method"] === "getwithdrawtransactionsbyheight") {
            await getBlkLogs(json_data, res);
            return;
        }
        if (json_data["method"] === "getexistdeposittransactions") {
            await getExistTxs(json_data, res);
            return;
        }
        if (json_data["method"] === "getillegalevidencebyheight") {
            await GetIllegalEvidenceByHeight(json_data, res);
             return;
        }
        if (json_data["method"] === "checkillegalevidence") {
            await CheckIllegalEvidence(json_data, res);
            return;
        }
        if (json_data["method"] === "sendsmallcrosstransaction") {
            await Smallcrosschaintransaction(json_data, res)
            return;
        }
        if (json_data["method"] === "getfaileddeposittransactions") {
            await FailedDepositTransactions(json_data, res)
            return;
        }
        if (json_data["method"] === "getfaileddeposittransactionbyhash") {
            await GetFailedDepositTxByHash(json_data, res)
            return;
        }
        if (json_data["method"] === "sendinvalidwithdrawtransaction") {
            await FailedWithdrawTxByHash(json_data, res)
            return;
        }
        if (json_data["method"] === "getprocessedinvalidwithdrawtransactions") {
            await  ProcessedFailedWithdrawTxs(json_data, res)
            return;
        }
        if (json_data["method"] === "getPledgeBillBurnTransactionByHeight") {
            await GetPledgeBillBurnLogsByHeight(json_data,res)
            return;
        }
    } catch (err) {
        common.reterr(err, res);
        return;
    }
    res.json({"result": "received"});
});

let server = app.listen('20652');
server.timeout = 360000;
console.log("Server started...");

process.on("SIGINT", () => {
    console.log("Shutting down...");
    process.exit();
});
