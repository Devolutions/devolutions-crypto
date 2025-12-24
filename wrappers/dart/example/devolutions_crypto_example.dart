import 'dart:convert';
import 'dart:typed_data';

// Note: After running `make bindings`, uncomment the following line:
// import 'package:devolutions_crypto/devolutions_crypto.dart';

void main() {
  print('Devolutions Crypto Dart Example');
  print('================================\n');

  // Note: The following examples will work after generating bindings with:
  // 1. Run: make bindings
  // 2. Uncomment the import above
  // 3. Uncomment the examples below

  // Example 1: Generate a key pair for asymmetric encryption
  exampleGenerateKeypair();

  // Example 2: Symmetric encryption
  exampleSymmetricEncryption();

  // Example 3: Asymmetric encryption
  exampleAsymmetricEncryption();

  // Example 4: Password hashing
  examplePasswordHashing();

  // Example 5: Secret sharing
  exampleSecretSharing();

  // Example 6: Digital signatures
  exampleDigitalSignatures();
}

void exampleGenerateKeypair() {
  print('Example 1: Generate Key Pair');
  print('----------------------------');

  // Uncomment after generating bindings:
  /*
  final keyPair = generateKeypair();
  print('Public key length: ${keyPair.publicKey.length} bytes');
  print('Private key length: ${keyPair.privateKey.length} bytes');
  print('Public key (hex): ${_bytesToHex(keyPair.publicKey)}');
  print('');
  */

  print('Run "make bindings" to generate Dart bindings first.\n');
}

void exampleSymmetricEncryption() {
  print('Example 2: Symmetric Encryption');
  print('-------------------------------');

  // Uncomment after generating bindings:
  /*
  final data = utf8.encode('Hello, Devolutions Crypto!');
  final key = Uint8List.fromList(List<int>.generate(32, (i) => i));

  try {
    final encrypted = encrypt(data, key);
    print('Original data: Hello, Devolutions Crypto!');
    final encHex = _bytesToHex(encrypted.sublist(0, 32));
    print('Encrypted (${encrypted.length} bytes): $encHex...');
    print('');
  } catch (e) {
    print('Error: $e\n');
  }
  */

  print('Run "make bindings" to generate Dart bindings first.\n');
}

void exampleAsymmetricEncryption() {
  print('Example 3: Asymmetric Encryption');
  print('--------------------------------');

  // Uncomment after generating bindings:
  /*
  final keyPair = generateKeypair();
  final data = utf8.encode('Secret message');

  try {
    final encrypted = encryptAsymmetric(data, keyPair.publicKey);
    print('Original data: Secret message');
    final encHex = _bytesToHex(encrypted.sublist(0, 32));
    print('Encrypted (${encrypted.length} bytes): $encHex...');
    print('');
  } catch (e) {
    print('Error: $e\n');
  }
  */

  print('Run "make bindings" to generate Dart bindings first.\n');
}

void examplePasswordHashing() {
  print('Example 4: Password Hashing');
  print('---------------------------');

  // Uncomment after generating bindings:
  /*
  final password = utf8.encode('mySecurePassword123');

  try {
    final hash = hashPassword(password, iterations: 10000);
    print('Password: mySecurePassword123');
    print('Hash length: ${hash.length} bytes');
    print('Hash (hex): ${_bytesToHex(hash.sublist(0, 32))}...');
    print('');
  } catch (e) {
    print('Error: $e\n');
  }
  */

  print('Run "make bindings" to generate Dart bindings first.\n');
}

void exampleSecretSharing() {
  print('Example 5: Secret Sharing');
  print('------------------------');

  // Uncomment after generating bindings:
  /*
  try {
    // Generate 5 shares, requiring 3 to reconstruct
    final shares = generateSharedKey(5, 3, length: 32);
    print('Generated ${shares.length} shares');
    print('Threshold: 3 shares required to reconstruct');
    print('Share 1 (hex): ${_bytesToHex(shares[0].sublist(0, 16))}...');
    print('Share 2 (hex): ${_bytesToHex(shares[1].sublist(0, 16))}...');
    print('');
  } catch (e) {
    print('Error: $e\n');
  }
  */

  print('Run "make bindings" to generate Dart bindings first.\n');
}

void exampleDigitalSignatures() {
  print('Example 6: Digital Signatures');
  print('----------------------------');

  // Uncomment after generating bindings:
  /*
  final signingKeyPair = generateSigningKeypair();
  final data = utf8.encode('Document to sign');

  try {
    final signature = sign(
      data,
      Uint8List.fromList([
        ...signingKeyPair.getPublicKey(),
        ...signingKeyPair.getPrivateKey(),
      ]),
    );
    print('Data: Document to sign');
    print('Signature length: ${signature.length} bytes');
    print('Signature (hex): ${_bytesToHex(signature)}');
    print('');
  } catch (e) {
    print('Error: $e\n');
  }
  */

  print('Run "make bindings" to generate Dart bindings first.\n');
}

// Helper function to convert bytes to hex string
String _bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
