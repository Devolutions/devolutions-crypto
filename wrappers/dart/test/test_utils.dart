import 'dart:typed_data';

/// Code ported from Kotlin tests
/// https://www.geeksforgeeks.org/check-whether-an-array-is-subarray-of-another-array/
extension ListUtils<T> on List<T> {
  bool isSubArray(List<T> data) {
    int i = 0;
    int j = 0;

    while (i < data.length && j < length) {
      if (data[i] == this[j]) {
        i += 1;
        j += 1;

        if (j == length) {
          return true;
        }
      } else {
        i = i - j + 1;
        j = 0;
      }
    }

    return false;
  }
}

/// Extension for Uint8List comparison
extension Uint8ListUtils on Uint8List {
  bool contentEquals(Uint8List other) {
    if (length != other.length) return false;
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) return false;
    }
    return true;
  }
}
