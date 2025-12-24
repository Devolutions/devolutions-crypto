import 'dart:convert';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('Conformity Tests', () {
    test('derive key pbkdf2 test', () {
      final derivedKey =
          deriveKeyPbkdf2(utf8.encode('testpassword'), null, iterations: 10000);
      final derivedKeyWithIterations = deriveKeyPbkdf2(
          utf8.encode('testPa\$\$'), null,
          iterations: 100);
      final derivedKeyWithSalt = deriveKeyPbkdf2(
          utf8.encode('testPa\$\$'),
          base64Decode('tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA='),
          iterations: 100);

      final expected =
          base64Decode('ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=');
      final expectedWithIterations =
          base64Decode('ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=');
      final expectedWithSalt =
          base64Decode('ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=');

      expect(derivedKey, equals(expected));
      expect(derivedKeyWithIterations, equals(expectedWithIterations));
      expect(derivedKeyWithSalt, equals(expectedWithSalt));
    });

    test('derive key argon2 test', () {
      final password = utf8.encode('password');
      final parameters = Argon2Parameters.newFromBytes(base64Decode(
          'AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ=='));
      final result = deriveKeyArgon2(password, parameters);

      final expected =
          base64Decode('AcEN6Cb1Om6tomZScAM725qiXMzaxaHlj3iMiT/Ukq0=');

      expect(result, equals(expected));
    });

    test('symmetric decrypt v1 test', () {
      final key =
          base64Decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=');
      final ciphertext = base64Decode(
          'DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==');

      final result = decrypt(ciphertext, key);

      final expected = utf8.encode('test Ciph3rtext~');

      expect(result, equals(expected));
    });

    test('symmetric decrypt with aad v1 test', () {
      final key =
          base64Decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=');
      final ciphertext = base64Decode(
          'DQwCAAEAAQCeKfbTqYjfVCEPEiAJjiypBstPmZz0AnpliZKoR+WXTKdj2f/4ops0++dDBVZ+XdyE1KfqxViWVc9djy/HSCcPR4nDehtNI69heGCIFudXfQ==');
      final aad = utf8.encode('this is some public data');

      final result = decryptWithAad(ciphertext, key, aad);

      final expected = utf8.encode('test Ciph3rtext~');

      expect(result, equals(expected));
    });

    test('symmetric decrypt v2 test', () {
      final key =
          base64Decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=');
      final ciphertext = base64Decode(
          'DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=');

      final result = decrypt(ciphertext, key);

      final expected = utf8.encode('test Ciph3rtext~2');

      expect(result, equals(expected));
    });

    test('symmetric decrypt with aad v2 test', () {
      final key =
          base64Decode('ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=');
      final ciphertext = base64Decode(
          'DQwCAAEAAgA9bh989dao0Pvaz1NpJTI5m7M4br2qVjZtFwXXoXZOlkCjtqU/uif4pbNCcpEodzeP4YG1QvfKVQ==');
      final aad = utf8.encode('this is some public data');

      final result = decryptWithAad(ciphertext, key, aad);

      final expected = utf8.encode('test Ciph3rtext~');

      expect(result, equals(expected));
    });

    test('asymmetric decrypt with aad v2 test', () {
      final privateKey =
          base64Decode('DQwBAAEAAQC9qf9UY1ovL/48ALGHL9SLVpVozbdjYsw0EPerUl3zYA==');
      final ciphertext = base64Decode(
          'DQwCAAIAAgB1u62xYeyppWf83QdWwbwGUt5QuiAFZr+hIiFEvMRbXiNCE3RMBNbmgQkLr/vME0BeQa+uUTXZARvJcyNXHyAE4tSdw6o/psU/kw/Z/FbsPw==');
      final aad = utf8.encode('this is some public data');

      final result = decryptAsymmetricWithAad(ciphertext, privateKey, aad);

      final expected = utf8.encode('testdata');

      expect(result, equals(expected));
    });

    test('password hashing v1 test', () {
      final hash1 = base64Decode(
          'DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw==');
      final hash2 = base64Decode(
          'DQwDAAAAAQAKAAAAmH1BBckBJYDD0xfiwkAk1xwKgw8a57YQT0Igm+Faa9LFamTeEJgqn/qHc2R/8XEyK2iLPkVy+IErdGLLtLKJ2g==');

      expect(verifyPassword(utf8.encode('password1'), hash1), isTrue);
      expect(verifyPassword(utf8.encode('password1'), hash2), isTrue);
    });

    test('signature v1 test', () {
      final publicKey =
          base64Decode('DQwFAAIAAQDeEvwlEigK5AXoTorhmlKP6+mbiUU2rYrVQ25JQ5xang==');
      final signature = base64Decode(
          'DQwGAAAAAQD82uRk4sFC8vEni6pDNw/vOdN1IEDg9cAVfprWJZ/JBls9Gi61cUt5u6uBJtseNGZFT7qKLvp4NUZrAOL8FH0K');

      expect(
          verifySignature(utf8.encode('this is a test'), publicKey, signature),
          isTrue);
      expect(
          verifySignature(utf8.encode('this is wrong'), publicKey, signature),
          isFalse);
    });
  });
}
