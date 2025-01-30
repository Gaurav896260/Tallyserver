const forge = require("node-forge");

// Generate ElGamal keys (public and private keys)
function generateElGamalKeyPair(bits) {
  const p = forge.prime.generateProbablePrime(bits);  // Generate a probable prime number
  const g = forge.random.getBytesSync(bits / 8);      // Random base for encryption
  const privateKey = forge.random.getBytesSync(bits / 8);  // Private key
  const y = new forge.jsbn(g).modPow(new forge.jsbn(privateKey), new forge.jsbn(p));  // Public key (g^x mod p)
  
  return {
    privateKey: privateKey.toString(),
    publicKey: { p, g, y: y.toString() }
  };
}

// ElGamal encryption function
function elGamalEncrypt(publicKey, message) {
  const { p, g, y } = publicKey;

  const k = forge.random.getBytesSync(128); // Generate a random 'k' for encryption

  // Ciphertext: (c1, c2)
  const c1 = new forge.jsbn(g).modPow(new forge.jsbn(k), new forge.jsbn(p));
  const c2 = new forge.jsbn(message).multiply(new forge.jsbn(y).modPow(new forge.jsbn(k), new forge.jsbn(p))).mod(new forge.jsbn(p));

  return { c1: c1.toString(), c2: c2.toString() };
}

// ElGamal decryption function
function elGamalDecrypt(privateKey, ciphertext, p) {
  const { c1, c2 } = ciphertext;
  const c1BigInt = new forge.jsbn(c1);
  const c2BigInt = new forge.jsbn(c2);
  const privateKeyBigInt = new forge.jsbn(privateKey);

  // Decrypt: m = (c2 * (c1^(-x))) mod p
  const s = c1BigInt.modPow(privateKeyBigInt.negate(), new forge.jsbn(p)); // c1^(-x) mod p
  const m = c2BigInt.multiply(s).mod(new forge.jsbn(p));

  return m.toString();
}
