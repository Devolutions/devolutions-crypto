import 'dart:convert';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('Symmetric Encryption Tests', () {
    test('encrypt/decrypt test', () {
      final data = utf8.encode('This is some test data');
      final key = generateKey();

      final encrypted = encrypt(data, key);
      final decrypted = decrypt(encrypted, key);

      expect(data.toList().isSubArray(encrypted.toList()), isFalse);
      expect(decrypted, equals(data));
    });

    test('encrypt/decrypt with AAD test', () {
      final data = utf8.encode('This is some test data');
      final aad = utf8.encode('This is some public data');

      final key = generateKey();

      final encrypted = encryptWithAad(data, key, aad);
      final decrypted = decryptWithAad(encrypted, key, aad);

      expect(data.toList().isSubArray(encrypted.toList()), isFalse);
      expect(decrypted, equals(data));
    });

    test('encrypt/decrypt with wrong AAD test', () {
      final data = utf8.encode('This is some test data');
      final aad = utf8.encode('This is some public data');
      final wrongAad = utf8.encode('this is some public data');

      final key = generateKey();

      final encrypted = encryptWithAad(data, key, aad);

      expect(
        () => decryptWithAad(encrypted, key, wrongAad),
        throwsA(isA<DevolutionsCryptoException>()),
      );
    });
  });
}
