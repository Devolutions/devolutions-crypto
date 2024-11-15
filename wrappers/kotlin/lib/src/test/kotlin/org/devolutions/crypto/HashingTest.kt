/*
 * This source file was generated by the Gradle 'init' task
 */
package org.devolutions.crypto

import kotlin.test.Test

class HashingTest {
    @Test
    fun passwordHashTest() {
        val password = "password".toByteArray(Charsets.UTF_8)
        val hash = hashPassword(password, 10u)

        assert(verifyPassword(password, hash))
    }

    @Test
    fun wrongPasswordTest() {
        val password = "password".toByteArray(Charsets.UTF_8)
        val hash = hashPassword(password, 10u)

        assert(!verifyPassword("pa\$\$word".toByteArray(), hash))
        assert(!verifyPassword("Password".toByteArray(), hash))
        assert(!verifyPassword("password1".toByteArray(), hash))
    }
}