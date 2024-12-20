/*
 * This source file was generated by the Gradle 'init' task
 */
package org.devolutions.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AsymmetricTest {
    @Test
    fun generateKeypairTest() {
        val keypair = generateKeypair()

        assert(!keypair.publicKey.isEmpty())
        assert(!keypair.privateKey.isEmpty())

        assert(!keypair.privateKey.contentEquals(keypair.publicKey))
    }

    @Test
    fun encryptDecryptAsymmetricTest() {
        val data = "This is some test data".toByteArray(Charsets.UTF_8)
        val keypair = generateKeypair()

        val encrypted = encryptAsymmetric(data, keypair.publicKey)
        val decrypted = decryptAsymmetric(encrypted, keypair.privateKey)

        assert(!data.asList().isSubArray(encrypted.asList()))
        assertContentEquals(data, decrypted)
    }

    @Test
    fun encryptDecryptAsymmetricWithAadTest() {
        val data = "This is some test data".toByteArray(Charsets.UTF_8)
        val aad = "This is some public data".toByteArray(Charsets.UTF_8)

        val keypair = generateKeypair()

        val encrypted = encryptAsymmetricWithAad(data, keypair.publicKey, aad)
        val decrypted = decryptAsymmetricWithAad(encrypted, keypair.privateKey, aad)

        assert(!data.asList().isSubArray(encrypted.asList()))
        assertContentEquals(data, decrypted)
    }

    @Test
    fun encryptDecryptAsymmetricWithWrongAadTest() {
        val data = "This is some test data".toByteArray(Charsets.UTF_8)
        val aad = "This is some public data".toByteArray(Charsets.UTF_8)
        val wrongAad = "this is some public data".toByteArray(Charsets.UTF_8)

        val keypair = generateKeypair()

        val encrypted = encryptAsymmetricWithAad(data, keypair.publicKey, aad)

        assertFailsWith<DevolutionsCryptoException> {
            decryptAsymmetricWithAad(encrypted, keypair.privateKey, wrongAad)
        }
    }

    @Test
    fun mixKeyExchangeTest() {
        val bobKeypair = generateKeypair()
        val aliceKeypair = generateKeypair()

        val bobShared = mixKeyExchange(bobKeypair.privateKey, aliceKeypair.publicKey)
        val aliceShared = mixKeyExchange(aliceKeypair.privateKey, bobKeypair.publicKey)

        assertEquals(bobShared.size, 32)
        assert(!bobShared.contentEquals(ByteArray(32) { 0 }))
        assertContentEquals(bobShared, aliceShared)
    }

    @Test
    fun mixKeyExchangeNotEqualsTest() {
        val bobKeypair = generateKeypair()
        val aliceKeypair = generateKeypair()
        val eveKeypair = generateKeypair()

        val bobAliceShared = mixKeyExchange(bobKeypair.privateKey, aliceKeypair.publicKey)
        val aliceBobShared = mixKeyExchange(aliceKeypair.privateKey, bobKeypair.publicKey)

        val eveBobShared = mixKeyExchange(eveKeypair.privateKey, bobKeypair.publicKey)
        val eveAliceShared = mixKeyExchange(eveKeypair.privateKey, aliceKeypair.publicKey)

        assert(!eveBobShared.contentEquals(bobAliceShared))
        assert(!eveBobShared.contentEquals(aliceBobShared))
        assert(!eveAliceShared.contentEquals(bobAliceShared))
        assert(!eveAliceShared.contentEquals(aliceBobShared))
    }
}