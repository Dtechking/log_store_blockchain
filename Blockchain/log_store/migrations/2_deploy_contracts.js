const LogFileReader = artifacts.require("LogFileReader");

module.exports = function (deployer) {
  deployer.deploy(LogFileReader, { gas: 6721975 });
};
