import 'package:devolutions_crypto_dart/devolutions_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    final awesome = generate_key(32);
    print(awesome);
    print("BABABABAB");
    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () {
      expect(awesome.length == 32, isTrue);
    });
  });
}
