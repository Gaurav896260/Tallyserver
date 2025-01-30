const mongoose = require("mongoose");

const VoterSchema = new mongoose.Schema({
  voterId: { type: String, required: true, unique: true },
  vote: { type: String, required: true },
  publicKey: {type: String, required: true },
  // privateKey: { type: String, required: true },
});

module.exports = mongoose.model("Voter", VoterSchema);
