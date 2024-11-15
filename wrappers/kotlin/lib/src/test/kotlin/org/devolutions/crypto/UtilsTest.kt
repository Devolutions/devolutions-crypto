/*
 * This source file was generated by the Gradle 'init' task
 */
package org.devolutions.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class UtilsTest {
    @Test
    fun generateKeyDefaultTest() {
        val key = generateKey()

        assertEquals(32, key.size)
        assert(!key.contentEquals(ByteArray(32) { 0 }))
    }

    @Test
    fun generateKeyLongerTest() {
        val key = generateKey(41u)

        assertEquals(41, key.size)
        assert(!key.contentEquals(ByteArray(41) { 0 }))
    }

    @Test
    fun generateKeyActuallyRandomTest() {
        val key1 = generateKey()
        val key2 = generateKey()

        assert(!key1.contentEquals(key2))
    }

    @Test
    fun deriveKeyPbkdfDefaultTest() {
        val password = "password".toByteArray()

        val result = deriveKeyPbkdf2(password, null, 10u)
        assertEquals(32, result.size)
        assert(!result.contentEquals(ByteArray(32) { 0 }))
    }

    @Test
    fun deriveKeyPbkdfLargerTest() {
        val password = "password".toByteArray()

        val result = deriveKeyPbkdf2(password, null, 10u, 41u)
        assertEquals(41, result.size)
        assert(!result.contentEquals(ByteArray(41) { 0 }))
    }

    @Test
    fun deriveKeyPbkdfDeterministicTest() {
        val password = "password".toByteArray()

        val result1 = deriveKeyPbkdf2(password, null, 10u)
        val result2 = deriveKeyPbkdf2(password, null, 10u)

        assertEquals(32, result1.size)
        assert(!result1.contentEquals(ByteArray(32) { 0 }))
        assertContentEquals(result1, result2)
    }

    @Test
    fun deriveKeyPbkdfDifferentTest() {
        val password = "password".toByteArray()
        val salt = "thisisasalt".toByteArray()
        val iterations = 10u

        val result = deriveKeyPbkdf2(password, salt, iterations)
        val differentPass = deriveKeyPbkdf2("pa\$\$word".toByteArray(), salt, iterations)
        val differentSalt = deriveKeyPbkdf2(password, "this1sasalt".toByteArray(), iterations)
        val differentIterations = deriveKeyPbkdf2(password, salt, 11u)

        assert(!result.contentEquals(differentPass))
        assert(!result.contentEquals(differentSalt))
        assert(!result.contentEquals(differentIterations))
    }

    @Test
    fun deriveKeyArgon2Test() {
        val parameters = Argon2ParametersBuilder().build()
        val password = "password".toByteArray()

        val result = deriveKeyArgon2(password, parameters)

        assertEquals(32, result.size)
        assert(!result.contentEquals(ByteArray(32) { 0 }))
    }

    @Test
    fun validateHeaderValidTest() {
        val validCiphertext = base64Decode("DQwCAAAAAQA=")
        val validPasswordHash = base64Decode("DQwDAAAAAQA=")
        val validShare = base64Decode("DQwEAAAAAQA=")
        val validPrivateKey = base64Decode("DQwBAAEAAQA=")
        val validPublicKey = base64Decode("DQwBAAEAAQA=")

        assert(validateHeader(validCiphertext, DataType.CIPHERTEXT))
        assert(validateHeader(validPasswordHash, DataType.PASSWORD_HASH))
        assert(validateHeader(validShare, DataType.SHARE))
        assert(validateHeader(validPublicKey, DataType.KEY))
        assert(validateHeader(validPrivateKey, DataType.KEY))
    }

    @Test
    fun validateHeaderInvalidTest() {
        val validCiphertext = base64Decode("DQwCAAAAAQA=")

        assert(!validateHeader(validCiphertext, DataType.PASSWORD_HASH))

        val invalidSignature = base64Decode("DAwBAAEAAQA=")
        val invalidType = base64Decode("DQwIAAEAAQA=")
        val invalidSubtype = base64Decode("DQwBAAgAAQA=")
        val invalidVersion = base64Decode("DQwBAAEACAA=")

        assert(!validateHeader(invalidSignature, DataType.KEY))
        assert(!validateHeader(invalidType, DataType.KEY))
        assert(!validateHeader(invalidSubtype, DataType.KEY))
        assert(!validateHeader(invalidVersion, DataType.KEY))

        val notLongEnough = base64Decode("DQwBAAEAAQ==")

        assert(!validateHeader(notLongEnough, DataType.KEY))
    }

    @Test
    fun base64EncodeTest() {
        val input = byteArrayOf(0x41, 0x42, 0x43, 0x44, 0x45)
        val expected = "QUJDREU="
        val result = base64Encode(input)

        assertEquals(expected, result)
    }

    @Test
    fun base64DecodeTest() {
        val input = "QUJDREU="
        val expected = byteArrayOf(0x41, 0x42, 0x43, 0x44, 0x45)
        val result = base64Decode(input)

        assertContentEquals(expected, result)
    }

    @Test
    fun base64UrlEncodeTest() {
        val input1 = "Ab6/".toByteArray()
        val expected1 = "QWI2Lw"
        val result1 = base64EncodeUrl(input1)

        assertEquals(expected1, result1)

        val input2 = "Ab6/75".toByteArray()
        val expected2 = "QWI2Lzc1"
        val result2 = base64EncodeUrl(input2)

        assertEquals(expected2, result2)

        val input3 = byteArrayOf(0xff.toByte(), 0xff.toByte(), 0xfe.toByte(), 0xff.toByte())
        val expected3 = "___-_w"
        val result3 = base64EncodeUrl(input3)

        assertEquals(expected3, result3)
    }

    @Test
    fun base64UrlDecodeTest() {
        val input1 = "QWI2Lw"
        val expected1 = "Ab6/".toByteArray()
        val result1 = base64DecodeUrl(input1)

        assertContentEquals(expected1, result1)

        val input2 = "QWI2Lzc1"
        val expected2 = "Ab6/75".toByteArray()
        val result2 = base64DecodeUrl(input2)

        assertContentEquals(expected2, result2)

        val input3 = "___-_w"
        val expected3 = byteArrayOf(0xff.toByte(), 0xff.toByte(), 0xfe.toByte(), 0xff.toByte())
        val result3 = base64DecodeUrl(input3)

        assertContentEquals(expected3, result3)
    }
}