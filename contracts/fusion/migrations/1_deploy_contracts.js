var FusionToken = artifacts.require("FusionToken");

module.exports = function(deployer, network, accounts) {
  deployer.deploy(FusionToken);
};
