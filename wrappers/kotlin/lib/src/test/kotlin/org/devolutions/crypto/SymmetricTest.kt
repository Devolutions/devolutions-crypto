/*
 * This source file was generated by the Gradle 'init' task
 */
package org.devolutions.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class SymmetricTest {
    @Test
    fun encryptDecryptTest() {
        val data = "This is some test data".toByteArray(Charsets.UTF_8)
        val key = generateKey()

        val encrypted = encrypt(data, key)
        val decrypted = decrypt(encrypted, key)

        assert(!data.asList().isSubArray(encrypted.asList()))
        assertContentEquals(data, decrypted)
    }

    @Test
    fun encryptDecryptWithAadTest() {
        val data = "This is some test data".toByteArray(Charsets.UTF_8)
        val aad = "This is some public data".toByteArray(Charsets.UTF_8)

        val key = generateKey()

        val encrypted = encryptWithAad(data, key, aad)
        val decrypted = decryptWithAad(encrypted, key, aad)

        assert(!data.asList().isSubArray(encrypted.asList()))
        assertContentEquals(data, decrypted)
    }

    @Test
    fun encryptDecryptWithWrongAadTest() {
        val data = "This is some test data".toByteArray(Charsets.UTF_8)
        val aad = "This is some public data".toByteArray(Charsets.UTF_8)
        val wrongAad = "this is some public data".toByteArray(Charsets.UTF_8)

        val key = generateKey()

        val encrypted = encryptWithAad(data, key, aad)

        assertFailsWith<DevolutionsCryptoException> {
            decryptWithAad(encrypted, key, wrongAad)
        }
    }
}