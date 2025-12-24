import 'dart:convert';
import 'dart:typed_data';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('Utils Tests', () {
    test('generate key default test', () {
      final key = generateKey();

      expect(key.length, equals(32));
      expect(
          key.contentEquals(Uint8List.fromList(List<int>.filled(32, 0))),
          isFalse);
    });

    test('generate key longer test', () {
      final key = generateKey(length: 41);

      expect(key.length, equals(41));
      expect(
          key.contentEquals(Uint8List.fromList(List<int>.filled(41, 0))),
          isFalse);
    });

    test('generate key actually random test', () {
      final key1 = generateKey();
      final key2 = generateKey();

      expect(key1.contentEquals(key2), isFalse);
    });

    test('derive key pbkdf2 default test', () {
      final password = utf8.encode('password');

      final result = deriveKeyPbkdf2(password, null, iterations: 10);
      expect(result.length, equals(32));
      expect(
          result.contentEquals(Uint8List.fromList(List<int>.filled(32, 0))),
          isFalse);
    });

    test('derive key pbkdf2 larger test', () {
      final password = utf8.encode('password');

      final result = deriveKeyPbkdf2(password, null, iterations: 10, length: 41);
      expect(result.length, equals(41));
      expect(
          result.contentEquals(Uint8List.fromList(List<int>.filled(41, 0))),
          isFalse);
    });

    test('derive key pbkdf2 deterministic test', () {
      final password = utf8.encode('password');

      final result1 = deriveKeyPbkdf2(password, null, iterations: 10);
      final result2 = deriveKeyPbkdf2(password, null, iterations: 10);

      expect(result1.length, equals(32));
      expect(
          result1.contentEquals(Uint8List.fromList(List<int>.filled(32, 0))),
          isFalse);
      expect(result1, equals(result2));
    });

    test('derive key pbkdf2 different test', () {
      final password = utf8.encode('password');
      final salt = utf8.encode('thisisasalt');
      const iterations = 10;

      final result = deriveKeyPbkdf2(password, salt, iterations: iterations);
      final differentPass =
          deriveKeyPbkdf2(utf8.encode('pa\$\$word'), salt, iterations: iterations);
      final differentSalt = deriveKeyPbkdf2(
          password, utf8.encode('this1sasalt'), iterations: iterations);
      final differentIterations =
          deriveKeyPbkdf2(password, salt, iterations: 11);

      expect(result.contentEquals(differentPass), isFalse);
      expect(result.contentEquals(differentSalt), isFalse);
      expect(result.contentEquals(differentIterations), isFalse);
    });

    test('derive key argon2 test', () {
      final parameters = Argon2ParametersBuilder().build();
      final password = utf8.encode('password');

      final result = deriveKeyArgon2(password, parameters);

      expect(result.length, equals(32));
      expect(
          result.contentEquals(Uint8List.fromList(List<int>.filled(32, 0))),
          isFalse);
    });

    test('validate header valid test', () {
      final validCiphertext = base64Decode('DQwCAAAAAQA=');
      final validPasswordHash = base64Decode('DQwDAAAAAQA=');
      final validShare = base64Decode('DQwEAAAAAQA=');
      final validPrivateKey = base64Decode('DQwBAAEAAQA=');
      final validPublicKey = base64Decode('DQwBAAEAAQA=');

      expect(validateHeader(validCiphertext, DataType.ciphertext), isTrue);
      expect(validateHeader(validPasswordHash, DataType.passwordHash), isTrue);
      expect(validateHeader(validShare, DataType.share), isTrue);
      expect(validateHeader(validPublicKey, DataType.key), isTrue);
      expect(validateHeader(validPrivateKey, DataType.key), isTrue);
    });

    test('validate header invalid test', () {
      final validCiphertext = base64Decode('DQwCAAAAAQA=');

      expect(validateHeader(validCiphertext, DataType.passwordHash), isFalse);

      final invalidSignature = base64Decode('DAwBAAEAAQA=');
      final invalidType = base64Decode('DQwIAAEAAQA=');
      final invalidSubtype = base64Decode('DQwBAAgAAQA=');
      final invalidVersion = base64Decode('DQwBAAEACAA=');

      expect(validateHeader(invalidSignature, DataType.key), isFalse);
      expect(validateHeader(invalidType, DataType.key), isFalse);
      expect(validateHeader(invalidSubtype, DataType.key), isFalse);
      expect(validateHeader(invalidVersion, DataType.key), isFalse);

      final notLongEnough = base64Decode('DQwBAAEAAQ==');

      expect(validateHeader(notLongEnough, DataType.key), isFalse);
    });

    test('base64 encode test', () {
      final input = Uint8List.fromList([0x41, 0x42, 0x43, 0x44, 0x45]);
      const expected = 'QUJDREU=';
      final result = base64Encode(input);

      expect(result, equals(expected));
    });

    test('base64 decode test', () {
      const input = 'QUJDREU=';
      final expected = Uint8List.fromList([0x41, 0x42, 0x43, 0x44, 0x45]);
      final result = base64Decode(input);

      expect(result, equals(expected));
    });

    test('base64 url encode test', () {
      final input1 = utf8.encode('Ab6/');
      const expected1 = 'QWI2Lw';
      final result1 = base64EncodeUrl(input1);

      expect(result1, equals(expected1));

      final input2 = utf8.encode('Ab6/75');
      const expected2 = 'QWI2Lzc1';
      final result2 = base64EncodeUrl(input2);

      expect(result2, equals(expected2));

      final input3 = Uint8List.fromList([0xff, 0xff, 0xfe, 0xff]);
      const expected3 = '___-_w';
      final result3 = base64EncodeUrl(input3);

      expect(result3, equals(expected3));
    });

    test('base64 url decode test', () {
      const input1 = 'QWI2Lw';
      final expected1 = utf8.encode('Ab6/');
      final result1 = base64DecodeUrl(input1);

      expect(result1, equals(expected1));

      const input2 = 'QWI2Lzc1';
      final expected2 = utf8.encode('Ab6/75');
      final result2 = base64DecodeUrl(input2);

      expect(result2, equals(expected2));

      const input3 = '___-_w';
      final expected3 = Uint8List.fromList([0xff, 0xff, 0xfe, 0xff]);
      final result3 = base64DecodeUrl(input3);

      expect(result3, equals(expected3));
    });
  });
}
