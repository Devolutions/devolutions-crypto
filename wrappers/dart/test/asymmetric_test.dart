import 'dart:convert';
import 'dart:typed_data';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('Asymmetric Encryption Tests', () {
    test('generate keypair test', () {
      final keypair = generateKeypair();

      expect(keypair.publicKey, isNotEmpty);
      expect(keypair.privateKey, isNotEmpty);
      expect(keypair.privateKey.contentEquals(keypair.publicKey), isFalse);
    });

    test('encrypt/decrypt asymmetric test', () {
      final data = utf8.encode('This is some test data');
      final keypair = generateKeypair();

      final encrypted = encryptAsymmetric(data, keypair.publicKey);
      final decrypted = decryptAsymmetric(encrypted, keypair.privateKey);

      expect(data.toList().isSubArray(encrypted.toList()), isFalse);
      expect(decrypted, equals(data));
    });

    test('encrypt/decrypt asymmetric with AAD test', () {
      final data = utf8.encode('This is some test data');
      final aad = utf8.encode('This is some public data');

      final keypair = generateKeypair();

      final encrypted =
          encryptAsymmetricWithAad(data, keypair.publicKey, aad);
      final decrypted =
          decryptAsymmetricWithAad(encrypted, keypair.privateKey, aad);

      expect(data.toList().isSubArray(encrypted.toList()), isFalse);
      expect(decrypted, equals(data));
    });

    test('encrypt/decrypt asymmetric with wrong AAD test', () {
      final data = utf8.encode('This is some test data');
      final aad = utf8.encode('This is some public data');
      final wrongAad = utf8.encode('this is some public data');

      final keypair = generateKeypair();

      final encrypted =
          encryptAsymmetricWithAad(data, keypair.publicKey, aad);

      expect(
        () => decryptAsymmetricWithAad(encrypted, keypair.privateKey, wrongAad),
        throwsA(isA<DevolutionsCryptoException>()),
      );
    });

    test('mix key exchange test', () {
      final bobKeypair = generateKeypair();
      final aliceKeypair = generateKeypair();

      final bobShared =
          mixKeyExchange(bobKeypair.privateKey, aliceKeypair.publicKey);
      final aliceShared =
          mixKeyExchange(aliceKeypair.privateKey, bobKeypair.publicKey);

      expect(bobShared.length, equals(32));
      expect(
          bobShared.contentEquals(Uint8List.fromList(List<int>.filled(32, 0))),
          isFalse);
      expect(bobShared, equals(aliceShared));
    });

    test('mix key exchange not equals test', () {
      final bobKeypair = generateKeypair();
      final aliceKeypair = generateKeypair();
      final eveKeypair = generateKeypair();

      final bobAliceShared =
          mixKeyExchange(bobKeypair.privateKey, aliceKeypair.publicKey);
      final aliceBobShared =
          mixKeyExchange(aliceKeypair.privateKey, bobKeypair.publicKey);

      final eveBobShared =
          mixKeyExchange(eveKeypair.privateKey, bobKeypair.publicKey);
      final eveAliceShared =
          mixKeyExchange(eveKeypair.privateKey, aliceKeypair.publicKey);

      expect(eveBobShared.contentEquals(bobAliceShared), isFalse);
      expect(eveBobShared.contentEquals(aliceBobShared), isFalse);
      expect(eveAliceShared.contentEquals(bobAliceShared), isFalse);
      expect(eveAliceShared.contentEquals(aliceBobShared), isFalse);
    });
  });
}
