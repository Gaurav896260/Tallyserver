const https = require("https");
const express = require("express");
const fs = require("fs");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const Voter = require("./Voter.js");
const crypto = require("crypto");
// const forge = require("node-forge");
require("dotenv").config();
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Generate ElGamal keys (public and private keys)
function generateElGamalKeyPair(bits) {
  const prime = crypto.createDiffieHellman(bits);
  prime.generateKeys();

  const p = BigInt(`0x${prime.getPrime().toString("hex")}`);
  const g = BigInt(`0x${prime.getGenerator().toString("hex")}`);
  const privateKey = BigInt(`0x${prime.getPrivateKey().toString("hex")}`);
  const y = modExp(g, privateKey, p);

  return {
    privateKey: privateKey.toString(16),
    publicKey: {
      p: p.toString(16),
      g: g.toString(16),
      y: y.toString(16),
    },
  };
}

// Efficient modular exponentiation
function modExp(base, exponent, modulus) {
  base = BigInt(base);
  exponent = BigInt(exponent);
  modulus = BigInt(modulus);

  let result = 1n;
  base = base % modulus;

  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent / 2n;
    base = (base * base) % modulus;
  }

  return result;
}

function stringToBigInt(str) {
  return BigInt("0x" + Buffer.from(str, "utf8").toString("hex"));
}

// ElGamal encryption function
function elGamalEncrypt(publicKey, message) {
  const p = BigInt(`0x${publicKey.p}`);
  const g = BigInt(`0x${publicKey.g}`);
  const y = BigInt(`0x${publicKey.y}`);

  const m = stringToBigInt(message);
  const k =
    (BigInt(`0x${crypto.randomBytes(32).toString("hex")}`) % (p - 1n)) + 1n;

  const c1 = modExp(g, k, p);
  const c2 = (m * modExp(y, k, p)) % p;

  return { c1: c1.toString(16), c2: c2.toString(16) };
}

// ElGamal decryption function
function elGamalDecrypt(privateKey, ciphertext, p) {
  const c1 = BigInt(`0x${ciphertext.c1}`);
  const c2 = BigInt(`0x${ciphertext.c2}`);
  const pBigInt = BigInt(`0x${p}`);
  const privateKeyBigInt = BigInt(`0x${privateKey}`);

  const s = modExp(c1, privateKeyBigInt, pBigInt);
  const sInv = modInverse(s, pBigInt);
  const m = (c2 * sInv) % pBigInt;

  return bigIntToString(m);
}

function bigIntToString(bigInt) {
  const hex = bigInt.toString(16);
  return Buffer.from(hex, "hex").toString("utf8");
}

function modInverse(a, m) {
  let m0 = m;
  let y = 0n,
    x = 1n;
  if (m === 1n) return 0n;

  while (a > 1n) {
    let q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = y;
    y = x - q * y;
    x = t;
  }

  if (x < 0n) x += m0;
  return x;
}

const elGamalKeys = generateElGamalKeyPair(1024);

mongoose
  .connect(
    "mongodb+srv://shuklag868:118331@tsplab1.8ayne.mongodb.net/?retryWrites=true&w=majority&appName=TSPlab1"
  )
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error(err));

app.post("/compute-tally", async (req, res) => {
  try {
    const votes = await Voter.find();
    if (!votes.length) {
      return res.status(404).json({ message: "No votes found" });
    }

    const decryptedVotes = votes.map((voter) => {
      const decryptedVoterId = elGamalDecrypt(
        elGamalKeys.privateKey,
        JSON.parse(voter.voterId), // Make sure to parse the encrypted data properly
        elGamalKeys.publicKey.p
      );
      const decryptedVote = elGamalDecrypt(
        elGamalKeys.privateKey,
        JSON.parse(voter.vote), // Parse encrypted vote
        elGamalKeys.publicKey.p
      );
      return { voterId: decryptedVoterId, vote: decryptedVote };
    });

    const results = decryptedVotes.reduce((acc, curr) => {
      acc[curr.vote] = (acc[curr.vote] || 0) + 1;
      return acc;
    }, {});

    res.json({ results });
  } catch (error) {
    console.error("Error fetching votes:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/record-vote", async (req, res) => {
  const { voterId, vote } = req.body;

  if (!voterId || !vote) {
    return res.status(400).json({ error: "Voter ID and vote are required." });
  }

  try {
    /// Encrypt voterId and vote using the same public key
    const encryptedVoterId = elGamalEncrypt(elGamalKeys.publicKey, voterId);
    const encryptedVote = elGamalEncrypt(elGamalKeys.publicKey, vote);

    const newVote = new Voter({
      voterId: JSON.stringify(encryptedVoterId), // Store as JSON strings
      vote: JSON.stringify(encryptedVote), // Store as JSON strings
      publicKey: JSON.stringify(elGamalKeys.publicKey),
    });
    await newVote.save();

    res.status(200).json({ message: "Vote successfully recorded." });
  } catch (error) {
    console.error("Error recording vote:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

const sslOptions = {
  key: fs.readFileSync("server.key"),
  cert: fs.readFileSync("server.crt"),
};

https.createServer(sslOptions, app).listen(3003, () => {
  console.log("Tally Server running on https://localhost:3003");
});
