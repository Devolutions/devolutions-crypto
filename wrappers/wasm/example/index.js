// Import library
import * as devolutionsCrypto from "devolutions-crypto";

// Generate a random key for the lifetime of the script
var key = devolutionsCrypto.generateKey();

// Declare a bunch of global variables to access the DOM
var enc = new TextEncoder();
var dec = new TextDecoder();

var params = new devolutionsCrypto.Argon2Parameters();
var keypair = devolutionsCrypto.deriveKeyPair(enc.encode("pass123"), params);

console.log(devolutionsCrypto.base64encode(keypair.private.bytes))
console.log(devolutionsCrypto.base64encode(keypair.public.bytes))

var public_key = devolutionsCrypto.PublicKey.from(keypair.public.bytes);
var private_key = devolutionsCrypto.PrivateKey.from(keypair.private.bytes);

var asymmetric_ciphertext = devolutionsCrypto.encryptAsymmetric(enc.encode("test_data"), public_key)
console.log(devolutionsCrypto.base64encode(asymmetric_ciphertext));
console.log(dec.decode(devolutionsCrypto.decryptAsymmetric(asymmetric_ciphertext, private_key)));

var publicBob = null;
var privateBob = null;

var publicAlice = null;
var privateAlice = null;

var encryptionInput = document.getElementById("encryptionInput");
var encryptionOutput = document.getElementById("encryptionOutput");

var hashPasswordPasswordInput = document.getElementById("hashPasswordPasswordInput");
var hashPasswordIterationsInput = document.getElementById("hashPasswordIterationsInput");
var hashPasswordOutput = document.getElementById("hashPasswordOutput");

var verifyPasswordPasswordInput = document.getElementById("verifyPasswordPasswordInput");
var verifyPasswordHashInput = document.getElementById("verifyPasswordHashInput");
var verifyPasswordOutput = document.getElementById("verifyPasswordOutput");

var generateSharedKeyNsharesInput = document.getElementById("generateSharedKeyNsharesInput");
var generateSharedKeyThresholdInput = document.getElementById("generateSharedKeyThresholdInput");
var generateSharedKeyLengthInput = document.getElementById("generateSharedKeyLengthInput");
var generateSharedKeyOutput = document.getElementById("generateSharedKeyOutput");

var joinSharesInput = document.getElementById("joinSharesInput");
var joinSharesOutput = document.getElementById("joinSharesOutput");

var outputalice = document.getElementById("alice");
var outputbob = document.getElementById("bob");

var outputalicemix = document.getElementById("alicemix");
var outputbobmix = document.getElementById("bobmix");

var base64input = document.getElementById("base64input");
var base64output = document.getElementById("base64output");

var generateKeyLengthInput = document.getElementById("generateKeyLengthInput");
var generateKeyOutput = document.getElementById("generateKeyOutput");

var deriveKeyPasswordInput = document.getElementById("deriveKeyPasswordInput");
var deriveKeySaltInput = document.getElementById("deriveKeySaltInput");
var deriveKeyIterationsInput = document.getElementById("deriveKeyIterationsInput");
var deriveKeyLengthInput = document.getElementById("deriveKeyLengthInput");
var deriveKeyOutput = document.getElementById("deriveKeyOutput");

var btnEncrypt = document.getElementById("btnEncrypt");
var btnDecrypt = document.getElementById("btnDecrypt");

var btnHashPassword = document.getElementById("btnHashPassword");
var btnVerifyPassword = document.getElementById("btnVerifyPassword");

var btnBob = document.getElementById("btnBob");
var btnAlice = document.getElementById("btnAlice");

var btnBobMix = document.getElementById("btnBobMix");
var btnAliceMix = document.getElementById("btnAliceMix");

var btnBase64Encode = document.getElementById("btnBase64Encode");
var btnBase64Decode = document.getElementById("btnBase64Decode");

var btnGenerateKey = document.getElementById("btnGenerateKey");
var btnGenerateSharedKey = document.getElementById("btnGenerateSharedKey");
var btnJoinShares = document.getElementById("btnJoinShares");
var btnDeriveKey = document.getElementById("btnDeriveKey");

// Add handlers to buttons

// Encryption
btnEncrypt.addEventListener("click", () => 
{
    let result = devolutionsCrypto.encrypt(enc.encode(encryptionInput.value),  key);
    encryptionOutput.value = devolutionsCrypto.base64encode(result);
});

btnDecrypt.addEventListener("click", () =>
{
    let buffer = devolutionsCrypto.base64decode(encryptionInput.value);

    let result = devolutionsCrypto.decrypt(buffer, key);
    encryptionOutput.value = dec.decode(result);

});

//Password Hasing
// Hash
btnHashPassword.addEventListener("click", () => {
    let password = enc.encode(hashPasswordPasswordInput.value);

    let iterations = parseInt(hashPasswordIterationsInput.value);
    if(!iterations) {66
        iterations = 10000;
    }

    hashPasswordOutput.value = devolutionsCrypto.base64encode(devolutionsCrypto.hashPassword(password, iterations));
});

//Verify
btnVerifyPassword.addEventListener("click", () => {
    let password = enc.encode(verifyPasswordPasswordInput.value);
    let hash = devolutionsCrypto.base64decode(verifyPasswordHashInput.value);

    verifyPasswordOutput.value = devolutionsCrypto.verifyPassword(password, hash);
});

// Keypair Generation
btnBob.addEventListener("click", () => {
    let result = devolutionsCrypto.generateKeyPair();

    publicBob = result.public;
    privateBob = result.private;

    outputbob.value = devolutionsCrypto.base64encode(publicBob.bytes);

});

btnAlice.addEventListener("click", () => {
    let result = devolutionsCrypto.generateKeyPair();

    publicAlice = result.public;
    privateAlice = result.private;

    outputalice.value = devolutionsCrypto.base64encode(publicAlice.bytes);
});

// Key Exchange
btnBobMix.addEventListener("click", () => {
    let result = devolutionsCrypto.mixKeyExchange(privateBob, publicAlice);
    outputbobmix.value = devolutionsCrypto.base64encode(result);
});

btnAliceMix.addEventListener("click", () => {
    let result = devolutionsCrypto.mixKeyExchange(privateAlice, publicBob);
    outputalicemix.value = devolutionsCrypto.base64encode(result);
});

// Secret Sharing
btnGenerateSharedKey.addEventListener("click", () => {
    let nShares = parseInt(generateSharedKeyNsharesInput.value);
    if(!nShares) {
        nShares = 5;
    }

    let threshold = parseInt(generateSharedKeyThresholdInput.value);
    if(!threshold) {
        threshold = 3;
    }

    let length = parseInt(generateSharedKeyLengthInput.value);
    if(!length) {
        length = 32
    }

    let shares = devolutionsCrypto.generateSharedKey(nShares, threshold, length);
    let output = ""
    shares.forEach(s => {
        output = output + devolutionsCrypto.base64encode(s) + "\n";
    });

    generateSharedKeyOutput.value = output.trim()
});

btnJoinShares.addEventListener("click", () => {
    let shares = joinSharesInput.value.split("\n").map((s) => {
        return devolutionsCrypto.base64decode(s)
    });

    joinSharesOutput.value = devolutionsCrypto.base64encode(devolutionsCrypto.joinShares(shares));
});

// Utils
// Base64
btnBase64Encode.addEventListener("click", () => {
    base64output.value = devolutionsCrypto.base64encode(enc.encode(base64input.value));
});

btnBase64Decode.addEventListener("click", () => {
    base64output.value = dec.decode(devolutionsCrypto.base64decode(base64input.value));
});

// Generate Key
btnGenerateKey.addEventListener("click", () => {
    let length = parseInt(generateKeyLengthInput.value);
    if(!length) {
        length = 32;
    }

    generateKeyOutput.value = devolutionsCrypto.base64encode(devolutionsCrypto.generateKey(length));
});

// Derive Key
btnDeriveKey.addEventListener("click", () => {
    let password = enc.encode(deriveKeyPasswordInput.value);

    let iterations = parseInt(deriveKeyIterationsInput.value);
    if(!iterations) {
        iterations = 10000;
    }

    let salt = deriveKeySaltInput.value;
    if(!salt) {
        salt = new Uint8Array(0);
    }
    else {
        salt = devolutionsCrypto.base64decode(salt);
    }

    let length = parseInt(deriveKeyLengthInput.value);
    if(!length) {
        length = 32;
    }

    deriveKeyOutput.value = devolutionsCrypto.base64encode(devolutionsCrypto.deriveKey(password, salt, iterations, length));
});
