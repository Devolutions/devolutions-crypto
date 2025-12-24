import 'dart:typed_data';

import 'package:devolutions_crypto/devolutions_crypto.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('Secret Sharing Tests', () {
    test('shared secret default test', () {
      final shares = generateSharedKey(5, 3);

      final shareGroup1 = shares.sublist(0, 3);
      final shareGroup2 = shares.sublist(1, 4);
      final shareGroup3 = shares.sublist(2, 5);

      final key1 = joinShares(shareGroup1);
      final key2 = joinShares(shareGroup2);
      final key3 = joinShares(shareGroup3);

      expect(key1.length, equals(32));
      expect(
          key1.contentEquals(Uint8List.fromList(List<int>.filled(32, 0))),
          isFalse);
      expect(key1, equals(key2));
      expect(key1, equals(key3));
    });

    test('shared secret larger test', () {
      final shares = generateSharedKey(5, 3, length: 41);

      final shareGroup1 = shares.sublist(0, 3);
      final shareGroup2 = shares.sublist(1, 4);
      final shareGroup3 = shares.sublist(2, 5);

      final key1 = joinShares(shareGroup1);
      final key2 = joinShares(shareGroup2);
      final key3 = joinShares(shareGroup3);

      expect(key1.length, equals(41));
      expect(
          key1.contentEquals(Uint8List.fromList(List<int>.filled(41, 0))),
          isFalse);
      expect(key1, equals(key2));
      expect(key1, equals(key3));
    });

    test('shared secret wrong params test', () {
      expect(
        () => generateSharedKey(3, 5),
        throwsA(isA<DevolutionsCryptoException>()),
      );
    });

    test('shared secret not enough shares', () {
      final shares = generateSharedKey(5, 3);
      final sharesGroup = shares.sublist(0, 2);
      expect(
        () => joinShares(sharesGroup),
        throwsA(isA<DevolutionsCryptoException>()),
      );
    });
  });
}
