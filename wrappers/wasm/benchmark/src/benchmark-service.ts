import {encrypt, decrypt, generateKey} from 'devolutions-crypto';

// Number of time to run the benchmark. Higher will give a more representative average in the end.
const NUMBER_OF_RUNS = 10

// Number of distinct data blob to encrypt for the "separated" results.
const NUMBER_OF_SAMPLES = 1000

// Size, in bytes, of each blob to encrypt
const PLAINTEXT_SIZE = 1000

// Runs the benchmark
export function benchmark() {
    let encryptTimeSeparatedSum = 0;
    let decryptTimeSeparatedSum = 0;
    let encryptTimeMergedSum = 0;
    let decryptTimeMergedSum = 0;

    // Runs the benchmark NUMBER_OF_RUNS times and get the averages.
    let i = 0;
    for(i = 0; i < NUMBER_OF_RUNS; i++) {
        let values = benchmarkPass();
        encryptTimeSeparatedSum += values.encryptTimeSeparated
        decryptTimeSeparatedSum += values.decryptTimeSeparated
        encryptTimeMergedSum += values.encryptTimeMerged
        decryptTimeMergedSum += values.decryptTimeMerged
    }

    let results = {encryptTimeSeparated: encryptTimeSeparatedSum / NUMBER_OF_RUNS,
        decryptTimeSeparated: decryptTimeSeparatedSum / NUMBER_OF_RUNS,
        encryptTimeMerged: encryptTimeMergedSum / NUMBER_OF_RUNS,
        decryptTimeMerged: decryptTimeMergedSum / NUMBER_OF_RUNS,
    }

    // Prints the results
    console.log(results)
}

// Run a single pass of the benchmark. To get more accurate results, run this multiple times and average the results.
function benchmarkPass() {
    // Generate a random encryption key for this run
    let key = generateKey()

    // Generate NUMBER_OF_SAMPLES blobs of random data of PLAINTEXT_SIZE bytes each.
    let plaintexts: any = []

    let i = 0;
    for(i < 0; i < NUMBER_OF_SAMPLES; i++) {
        let p = new Uint8Array(PLAINTEXT_SIZE)
        crypto.getRandomValues(p)
        plaintexts.push(p)
    }

    let {ciphertexts, flatCiphertext, encryptTimeSeparated, encryptTimeMerged} = benchmarkEncrypt(plaintexts, key)
    let {outputPlaintexts, outputFlatPlaintext, decryptTimeSeparated, decryptTimeMerged} = benchmarkDecrypt(ciphertexts, flatCiphertext, key);

    return {encryptTimeSeparated, encryptTimeMerged, decryptTimeSeparated, decryptTimeMerged};
}

// Encrypts the different plaintexts separately and also encrypts them all at once after flattening the arrays.
// Returns the ciphertexts and the time it took to complete.
function benchmarkEncrypt(plaintexts: [Uint8Array], key: Uint8Array) {
    // Encrypts each blobs individually
    let timeStart = performance.now();
    let ciphertexts = plaintexts.map(p => {
        return encrypt(p, key)
    });
    let timeStop = performance.now();

    let encryptTimeSeparated = timeStop - timeStart;

    // Flatten the arrays to merge the plaintexts
    let flatPlaintext = Uint8Array.from(plaintexts.map(((p) => Array.prototype.slice.call(p))).flat())

    // Encrypt the full plaintext at once.
    timeStart = performance.now()

    let flatCiphertext = encrypt(flatPlaintext, key)

    timeStop = performance.now()

    let encryptTimeMerged = timeStop - timeStart;

    return {ciphertexts, flatCiphertext, encryptTimeSeparated, encryptTimeMerged};
}

// Encrypts the different ciphertext separately and also decrypts them all at once after flattening the arrays.
// Returns the plaintexts and the time it took to complete.
function benchmarkDecrypt(ciphertexts: Uint8Array[], flatCiphertext: Uint8Array, key: Uint8Array) {
    // Decrypt each ciphertexts individually
    let timeStart = performance.now();
    let outputPlaintexts = ciphertexts.map(c => {
        return decrypt(c, key)
    });
    let timeStop = performance.now();

    let decryptTimeSeparated = timeStop - timeStart;

    // Decrypt the full ciphertext at once.
    timeStart = performance.now()

    let outputFlatPlaintext = decrypt(flatCiphertext, key)

    timeStop = performance.now()

    let decryptTimeMerged = timeStop - timeStart;

    return {outputPlaintexts, outputFlatPlaintext, decryptTimeSeparated, decryptTimeMerged};
}
