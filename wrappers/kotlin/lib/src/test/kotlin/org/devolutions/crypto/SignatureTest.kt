/*
 * This source file was generated by the Gradle 'init' task
 */
package org.devolutions.crypto

import kotlin.test.Test

class SignatureTest {
    @Test
    fun signatureTest() {
        val data = "this is a test".toByteArray()
        val keypair = generateSigningKeypair()

        val signature = sign(data, keypair.getPrivateKey())

        assert(verifySignature(data, keypair.getPublicKey(), signature))
    }

    @Test
    fun wrongSignatureTest() {
        val data = "this is test data".toByteArray()
        val wrongData = "this is wrong data".toByteArray()
        val keypair = generateSigningKeypair()

        val signature = sign(data, keypair.getPrivateKey())

        assert(!verifySignature(wrongData, keypair.getPublicKey(), signature))
    }
}