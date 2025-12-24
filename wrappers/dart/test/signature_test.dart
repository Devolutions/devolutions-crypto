import 'dart:convert';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('Signature Tests', () {
    test('signature test', () {
      final data = utf8.encode('this is a test');
      final keypair = generateSigningKeypair();

      final signature = sign(data, keypair.getPrivateKey());

      expect(verifySignature(data, keypair.getPublicKey(), signature), isTrue);
    });

    test('wrong signature test', () {
      final data = utf8.encode('this is test data');
      final wrongData = utf8.encode('this is wrong data');
      final keypair = generateSigningKeypair();

      final signature = sign(data, keypair.getPrivateKey());

      expect(
          verifySignature(wrongData, keypair.getPublicKey(), signature),
          isFalse);
    });
  });
}
