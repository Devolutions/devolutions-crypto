import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:devolutions_crypto/devolutions_crypto.dart';

void main() {
  group('Devolutions Crypto Tests', () {
    test('generate key pair - verify native assets work', () {
      final key = generateKey();
      expect(key.length, equals(32));

      final keyPair = generateKeypair();
      expect(keyPair.publicKey, isNotEmpty);
      expect(keyPair.privateKey, isNotEmpty);
      print('✓ Native assets working! Generated key pair successfully.');
      print('  Public key length: ${keyPair.publicKey.length}');
      print('  Private key length: ${keyPair.privateKey.length}');
    });

    // Uncomment after generating bindings:
    /*
    group('Key Generation', () {
      test('generate key pair', () {
        final keyPair = generateKeypair();
        expect(keyPair.publicKey, isNotEmpty);
        expect(keyPair.privateKey, isNotEmpty);
        expect(keyPair.publicKey.length, equals(32));
        expect(keyPair.privateKey.length, equals(32));
      });

      test('generate signing key pair', () {
        final signingKeyPair = generateSigningKeypair();
        expect(signingKeyPair.getPublicKey(), isNotEmpty);
        expect(signingKeyPair.getPrivateKey(), isNotEmpty);
      });
    });

    group('Symmetric Encryption', () {
      test('encrypt and data should change', () {
        final data = utf8.encode('Hello, World!');
        final key = Uint8List.fromList(List<int>.generate(32, (i) => i));

        final encrypted = encrypt(data, key);

        expect(encrypted, isNotEmpty);
        expect(encrypted.length, greaterThan(data.length));
        expect(encrypted, isNot(equals(data)));
      });

      test('encrypt with AAD', () {
        final data = utf8.encode('Secret data');
        final key = Uint8List.fromList(List<int>.generate(32, (i) => i * 2));
        final aad = utf8.encode('metadata');

        final encrypted = encryptWithAad(data, key, aad);

        expect(encrypted, isNotEmpty);
        expect(encrypted.length, greaterThan(data.length));
      });

      test('encrypt same data twice produces different ciphertext', () {
        final data = utf8.encode('Same data');
        final key = Uint8List.fromList(List<int>.generate(32, (i) => i));

        final encrypted1 = encrypt(data, key);
        final encrypted2 = encrypt(data, key);

        // Due to random nonce/IV, should be different
        expect(encrypted1, isNot(equals(encrypted2)));
      });
    });

    group('Asymmetric Encryption', () {
      test('encrypt asymmetric', () {
        final keyPair = generateKeypair();
        final data = utf8.encode('Secret message');

        final encrypted = encryptAsymmetric(data, keyPair.publicKey);

        expect(encrypted, isNotEmpty);
        expect(encrypted.length, greaterThan(data.length));
      });

      test('encrypt asymmetric with AAD', () {
        final keyPair = generateKeypair();
        final data = utf8.encode('Secret message');
        final aad = utf8.encode('metadata');

        final encrypted =
            encryptAsymmetricWithAad(data, keyPair.publicKey, aad);

        expect(encrypted, isNotEmpty);
      });
    });

    group('Password Hashing', () {
      test('hash password', () {
        final password = utf8.encode('mySecurePassword123');

        final hash = hashPassword(password);

        expect(hash, isNotEmpty);
        expect(hash.length, greaterThan(0));
      });

      test('hash password with custom iterations', () {
        final password = utf8.encode('testPassword');

        final hash = hashPassword(password, iterations: 5000);

        expect(hash, isNotEmpty);
      });

      test('same password produces different hashes', () {
        final password = utf8.encode('samePassword');

        final hash1 = hashPassword(password);
        final hash2 = hashPassword(password);

        // Due to random salt, should be different
        expect(hash1, isNot(equals(hash2)));
      });
    });

    group('Secret Sharing', () {
      test('generate shared key', () {
        final shares = generateSharedKey(5, 3);

        expect(shares, hasLength(5));
        expect(shares[0], isNotEmpty);
        expect(shares[1], isNotEmpty);
      });

      test('generate shared key with custom length', () {
        final shares = generateSharedKey(3, 2, length: 64);

        expect(shares, hasLength(3));
        expect(shares[0].length, greaterThan(0));
      });

      test('threshold cannot exceed total shares', () {
        expect(
          () => generateSharedKey(3, 5),
          throwsA(isA<DevolutionsCryptoError>()),
        );
      });
    });

    group('Digital Signatures', () {
      test('sign data', () {
        final signingKeyPair = generateSigningKeypair();
        final data = utf8.encode('Document to sign');
        final keypairBytes = Uint8List.fromList([
          ...signingKeyPair.getPublicKey(),
          ...signingKeyPair.getPrivateKey(),
        ]);

        final signature = sign(data, keypairBytes);

        expect(signature, isNotEmpty);
        expect(signature.length, greaterThan(0));
      });

      test('same data produces same signature with same key', () {
        final signingKeyPair = generateSigningKeypair();
        final data = utf8.encode('Document to sign');
        final keypairBytes = Uint8List.fromList([
          ...signingKeyPair.getPublicKey(),
          ...signingKeyPair.getPrivateKey(),
        ]);

        final signature1 = sign(data, keypairBytes);
        final signature2 = sign(data, keypairBytes);

        expect(signature1, equals(signature2));
      });
    });

    group('Error Handling', () {
      test('invalid key length throws error', () {
        final data = utf8.encode('test');
        final invalidKey = Uint8List.fromList([1, 2, 3]); // Too short

        expect(
          () => encrypt(data, invalidKey),
          throwsA(isA<DevolutionsCryptoError>()),
        );
      });

      test('empty data handling', () {
        final data = Uint8List.fromList([]);
        final key = Uint8List.fromList(List<int>.generate(32, (i) => i));

        // Should handle empty data gracefully
        expect(() => encrypt(data, key), returnsNormally);
      });
    });
    */
  });
}
