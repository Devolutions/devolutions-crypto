package org.devolutions.crypto

// Code is ported from this post:
// https://www.geeksforgeeks.org/check-whether-an-array-is-subarray-of-another-array/
fun <T> List<T>.isSubArray(data: List<T>): Boolean {
    var i = 0
    var j = 0

    while (i < data.size && j < this.size) {
        if (data[i] == this[j]) {
            i += 1;
            j += 1;

            if (j == this.size) {
                return true
            }
        } else {
            i = i - j + 1
            j = 0
        }
    }

    return false
}
