import 'dart:convert';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('Password Hashing Tests', () {
    test('password hash test', () {
      final password = utf8.encode('password');
      final hash = hashPassword(password, iterations: 10);

      expect(verifyPassword(password, hash), isTrue);
    });

    test('wrong password test', () {
      final password = utf8.encode('password');
      final hash = hashPassword(password, iterations: 10);

      expect(verifyPassword(utf8.encode('pa\$\$word'), hash), isFalse);
      expect(verifyPassword(utf8.encode('Password'), hash), isFalse);
      expect(verifyPassword(utf8.encode('password1'), hash), isFalse);
    });
  });
}
