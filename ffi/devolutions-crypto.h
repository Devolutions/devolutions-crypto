#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * Compare two byte arrays with constant-time equality.
 * # Arguments
 *  * `x` - Pointer to the first value to compare.
 *  * `x_length` - Length of the first value to compare.
 *  * `y` - Pointer to the second value to compare.
 *  * `y_length` - Length of the second value to compare.
 * # Returns
 * Returns 0 if the values are not equal is invalid or 1 if the values are equal. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t ConstantTimeEquals(const uint8_t *x,
                           size_t x_length,
                           const uint8_t *y,
                           size_t y_length);

/**
 * Decode a base64 string to bytes.
 * # Arguments
 *  * input - Pointer to the string to decode.
 *  * input_length - Length of the string to decode.
 *  * output - Pointer to the output buffer.
 *  * output_length - Length of the output buffer.
 * # Returns
 * Returns the size of the decoded string.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t Decode(const uint8_t *input,
               size_t input_length,
               uint8_t *output,
               size_t output_length);

/**
 * Decode a base64 string to bytes using base64url.
 * # Arguments
 *  * input - Pointer to the string to decode.
 *  * input_length - Length of the string to decode.
 *  * output - Pointer to the output buffer.
 *  * output_length - Length of the output buffer.
 * # Returns
 * Returns the size of the decoded string.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t DecodeUrl(const uint8_t *input,
                  size_t input_length,
                  uint8_t *output,
                  size_t output_length);

/**
 * Decrypt a data blob
 * # Arguments
 *  * `data` - Pointer to the data to decrypt.
 *  * `data_length` - Length of the data to decrypt.
 *  * `key` - Pointer to the key to use to decrypt.
 *  * `key_length` - Length of the key to use to decrypt.
 *  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
 *             Pass null if there is not additionnal data to authenticate.
 *  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
 *  * `result` - Pointer to the buffer to write the plaintext to.
 *  * `result_length` - Length of the buffer to write the plaintext to.
 *                     The safest size is the same size as the ciphertext.
 * # Returns
 * This returns the length of the plaintext. If there is an error, it will return the
 *     appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t Decrypt(const uint8_t *data,
                size_t data_length,
                const uint8_t *key,
                size_t key_length,
                const uint8_t *aad,
                size_t aad_length,
                uint8_t *result,
                size_t result_length);

/**
 * Decrypt a data blob
 * # Arguments
 *  * `data` - Pointer to the data to decrypt.
 *  * `data_length` - Length of the data to decrypt.
 *  * `private_key` - Pointer to the private key to use to decrypt.
 *  * `private_key_length` - Length of the private key to use to decrypt.
 *  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
 *             Pass null if there is not additionnal data to authenticate.
 *  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
 *  * `result` - Pointer to the buffer to write the plaintext to.
 *  * `result_length` - Length of the buffer to write the plaintext to.
 *                     The safest size is the same size as the ciphertext.
 * # Returns
 * This returns the length of the plaintext. If there is an error, it will return the
 *     appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t DecryptAsymmetric(const uint8_t *data,
                          size_t data_length,
                          const uint8_t *private_key,
                          size_t private_key_length,
                          const uint8_t *aad,
                          size_t aad_length,
                          uint8_t *result,
                          size_t result_length);

/**
 * Derive a key with Argon2 to create a new one. Can be used with a password.
 * # Arguments
 *  * key - Pointer to the key to derive.
 *  * key_length - Length of the key to derive.
 *  * argon2_parameters - Pointer to the buffer containing the argon2 parameters.
 *  * argon2_parameters_length - Length of the argon2 parameters to use.
 *  * result - Pointer to the buffer to write the new key to.
 *  * result_length - Length of buffer to write the key to.
 * # Returns
 * Returns 0 if the operation is successful. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t DeriveKeyArgon2(const uint8_t *key,
                        size_t key_length,
                        const uint8_t *argon2_parameters,
                        size_t argon2_parameters_length,
                        uint8_t *result,
                        size_t result_length);

/**
 * Derive a key with PBKDF2 to create a new one. Can be used with a password.
 * # Arguments
 *  * key - Pointer to the key to derive.
 *  * key_length - Length of the key to derive.
 *  * salt - Pointer to the buffer containing the salt. Can be null.
 *  * salt_length - Length of the salt to use.
 *  * result - Pointer to the buffer to write the new key to.
 *  * result_length - Length of buffer to write the key to.
 * # Returns
 * Returns 0 if the operation is successful. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t DeriveKeyPbkdf2(const uint8_t *key,
                        size_t key_length,
                        const uint8_t *salt,
                        size_t salt_length,
                        uint32_t niterations,
                        uint8_t *result,
                        size_t result_length);

/**
 * Encode a byte array to a base64 string.
 * # Arguments
 *  * input - Pointer to the buffer to encode.
 *  * input_length - Length of the buffer to encode.
 *  * output - Pointer to the output buffer.
 *  * output_length - Length of the output buffer.
 * # Returns
 * Returns the size, in bytes, of the output buffer.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t Encode(const uint8_t *input,
               size_t input_length,
               uint8_t *output,
               size_t output_length);

/**
 * Encode a byte array to a base64 string using base64url.
 * # Arguments
 *  * input - Pointer to the buffer to encode.
 *  * input_length - Length of the buffer to encode.
 *  * output - Pointer to the output buffer.
 *  * output_length - Length of the output buffer.
 * # Returns
 * Returns the size, in bytes, of the output buffer.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t EncodeUrl(const uint8_t *input,
                  size_t input_length,
                  uint8_t *output,
                  size_t output_length);

/**
 * Encrypt a data blob
 * # Arguments
 *  * `data` - Pointer to the data to encrypt.
 *  * `data_length` - Length of the data to encrypt.
 *  * `key` - Pointer to the key to use to encrypt.
 *  * `key_length` - Length of the key to use to encrypt.
 *  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
 *             Pass null if there is not additionnal data to authenticate.
 *  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
 *  * `result` - Pointer to the buffer to write the ciphertext to.
 *  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
 *                         calling EncryptSize() beforehand.
 *  * `version` - Version to use. Use 0 for the latest one.
 * # Returns
 * This returns the length of the ciphertext. If there is an error, it will return the
 *     appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t Encrypt(const uint8_t *data,
                size_t data_length,
                const uint8_t *key,
                size_t key_length,
                const uint8_t *aad,
                size_t aad_length,
                uint8_t *result,
                size_t result_length,
                uint16_t version);

/**
 * Encrypt a data blob
 * # Arguments
 *  * `data` - Pointer to the data to encrypt.
 *  * `data_length` - Length of the data to encrypt.
 *  * `public_key` - Pointer to the public key to use to encrypt.
 *  * `public_key_length` - Length of the public key to use to encrypt.
 *  * `aad` - Pointer to additionnal data to authenticate alongside the ciphertext.
 *             Pass null if there is not additionnal data to authenticate.
 *  * `aad_length` - Length of the additionnal data to authenticate. Pass 0 if there is no data.
 *  * `result` - Pointer to the buffer to write the ciphertext to.
 *  * `result_length` - Length of the buffer to write the ciphertext to. You can get the value by
 *                         calling EncryptAsymmetricSize() beforehand.
 *  * `version` - Version to use. Use 0 for the latest one.
 * # Returns
 * This returns the length of the asymmetric ciphertext. If there is an error, it will return the
 *     appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t EncryptAsymmetric(const uint8_t *data,
                          size_t data_length,
                          const uint8_t *public_key,
                          size_t public_key_length,
                          const uint8_t *aad,
                          size_t aad_length,
                          uint8_t *result,
                          size_t result_length,
                          uint16_t version);

/**
 * Get the size of the resulting asymmetric ciphertext.
 * # Arguments
 *  * data_length - Length of the plaintext.
 * # Returns
 * Returns the length of the asymmetric ciphertext to input as `result_length` in `EncryptAsymmetric()`.
 */
int64_t EncryptAsymmetricSize(size_t data_length,
                              uint16_t version);

/**
 * Get the size of the resulting ciphertext.
 * # Arguments
 *  * data_length - Length of the plaintext.
 * # Returns
 * Returns the length of the ciphertext to input as `result_length` in `Encrypt()`.
 */
int64_t EncryptSize(size_t data_length, uint16_t version);

void FreeOnlineDecryptor(void *ptr);

void FreeOnlineEncryptor(void *ptr);

/**
 * Generate a key using a CSPRNG.
 * # Arguments
 *  * key - Pointer to the buffer to fill with random values.
 *  * key_length - Length of the buffer to fill.
 * # Returns
 * Returns 0 if the operation is successful. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t GenerateKey(uint8_t *key,
                    size_t key_length);

/**
 * Generate a key pair to perform a key exchange. Must be used with MixKey()
 * # Arguments
 *  * `private` - Pointer to the buffer to write the private key to.
 *  * `private_length` - Length of the buffer to write the private key to.
 *                         You can get the value by calling `GenerateKeyPairSize()` beforehand.
 *  * `public` - Pointer to the buffer to write the public key to.
 *  * `public_length` - Length of the buffer to write the public key to.
 *                         You can get the value by calling `GenerateKeyPairSize()` beforehand.
 * # Returns
 * Returns 0 if the generation worked. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t GenerateKeyPair(uint8_t *private_,
                        size_t private_length,
                        uint8_t *public_,
                        size_t public_length);

/**
 * Get the size of the keys in the key exchange key pair.
 * # Returns
 * Returns the length of the keys to input as `private_length`
 *     and `public_length` in `GenerateKeyPair()`.
 */
int64_t GenerateKeyPairSize(void);

/**
 * Generates a secret key shared amongst multiple actor.
 * # Arguments
 *  * n_shares - The number of shares to generate.
 *  * threshold - The number of shares required to regenerate the secret.
 *  * length - The length of the generated secret
 *  * shares - The output buffers. This is a 2-dimensionnal array representing the shares.
 * # Returns
 * Returns 0 if the operation is successful. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t GenerateSharedKey(uint8_t n_shares,
                          uint8_t threshold,
                          size_t length,
                          uint8_t *const *shares);

/**
 * The size, in bytes, of each resulting shares
 * # Arguments
 *  * secret_length - The length of the desired secret
 * # Returns
 * Returns the size, in bytes, of each resulting shares.
 */
int64_t GenerateSharedKeySize(size_t secret_length);

/**
 * Generate a key pair to sign and verify data with.
 * # Arguments
 *  * `keypair` - Pointer to the buffer to write the keypair to.
 *  * `keypair_length` - Length of the buffer to write the keypair to.
 *                         You can get the value by calling `GenerateSigningKeyPairSize()` beforehand.
 *  * `version` - Version to use. Use 0 for the latest one.
 * # Returns
 * Returns 0 if the generation worked. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t GenerateSigningKeyPair(uint8_t *keypair,
                               size_t keypair_length,
                               uint16_t version);

/**
 * Get the size of the keypair used for signing.
 * # Returns
 * Returns the length of the keypair to input as `keypair_length`
 *   in `GenerateSigningKeyPair()`.
 */
int64_t GenerateSigningKeyPairSize(uint16_t _version);

/**
 * Get the default Argon2Parameters struct values.
 * # Arguments
 *  * argon2_parameters - Pointer to the output buffer.
 *  * argon2_parameters_length - Length of the output buffer.
 * # Returns
 * Returns 0 if the operation is successful.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t GetDefaultArgon2Parameters(uint8_t *argon2_parameters,
                                   size_t argon2_parameters_length);

/**
 * Size of the Argon2Parameters struct.
 * # Returns
 * Returns 0 if the operation is successful.
 */
int64_t GetDefaultArgon2ParametersSize(void);

/**
 * Get the public part of a keypair used to sign data.
 * # Arguments
 *  * `keypair` - Pointer to the buffer containing the keypair.
 *  * `keypair_length` - Length of the buffer containing the keypair.
 *  * `public` - Pointer to the buffer to write the public key to.
 *  * `public_length` - Length of the buffer to write the public key to.
 *                         You can get the value by calling `GetSigningPublicKeySize()` beforehand.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t GetSigningPublicKey(const uint8_t *keypair,
                            size_t keypair_length,
                            uint8_t *public_,
                            size_t public_length);

/**
 * Get the size of the public key used for signing.
 * # Returns
 * Returns the length of the public key to input as `public_length`
 *   in `GetSigningPublicKey()`.
 */
int64_t GetSigningPublicKeySize(const uint8_t *_keypair, size_t _keypair_length);

/**
 * Hash a password using a high-cost algorithm.
 * # Arguments
 *  * `password` - Pointer to the password to hash.
 *  * `password_length` - Length of the password to hash.
 *  * `iterations` - Number of iterations of the password hash.
 *                   A higher number is slower but harder to brute-force. The recommended is 10000,
 *                   but the number can be set by the user.
 *  * `result` - Pointer to the buffer to write the hash to.
 *  * `result_length` - Length of the buffer to write the hash to. You can get the value by
 *                         calling HashPasswordLength() beforehand.
 * # Returns
 * This returns the length of the hash. If there is an error, it will return the
 *     appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t HashPassword(const uint8_t *password,
                     size_t password_length,
                     uint32_t iterations,
                     uint8_t *result,
                     size_t result_length);

/**
 * Get the size of the resulting hash.
 * # Returns
 * Returns the length of the hash to input as `result_length` in `HashPassword()`.
 */
int64_t HashPasswordLength(void);

/**
 * Join multiple shares to regenerate a shared secret.
 * # Arguments
 *  * n_shares - The number of shares sent to the method
 *  * share_length - The length of each share
 *  * shares - The shares to join
 *  * secret - The output buffer to write the shared secret to.
 *  * secret_length - The length of the output buffer. Get the value with JoinSharesSize.
 * # Returns
 * Returns 0 if the operation is successful. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t JoinShares(size_t n_shares,
                   size_t share_length,
                   const uint8_t *const *shares,
                   uint8_t *secret,
                   size_t secret_length);

/**
 * The size, in bytes, of the resulting secret
 * # Arguments
 *  * share_length - The length of a share
 * # Returns
 * Returns the size, in bytes, of each resulting secret.
 */
int64_t JoinSharesSize(size_t share_length);

/**
 *  Size, in bits, of the key used for the current Encrypt() implementation.
 * # Returns
 * Returns the size, in bits, of the key used fot the current Encrypt() implementation.
 */
uint32_t KeySize(void);

/**
 * Performs a key exchange.
 * # Arguments
 *  * `private` - Pointer to the buffer containing the private key.
 *  * `private_length` - Length of the buffer containing the private key.
 *  * `public` - Pointer to the buffer containing the public key.
 *  * `public_length` - Length of the buffer containing the public key.
 *  * `shared` - Pointer to the buffer to write the resulting shared key.
 *  * `shared_size` - Length of the buffer containing the shared key.
 * # Returns
 * Returns 0 if the key exchange worked. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t MixKeyExchange(const uint8_t *private_,
                       size_t private_size,
                       const uint8_t *public_,
                       size_t public_size,
                       uint8_t *shared,
                       size_t shared_size);

/**
 * Get the size of the keys in the key exchange key pair.
 * # Returns
 * Returns the length of the keys to input as `shared_length` in `MixKeyExchange()`.
 */
int64_t MixKeyExchangeSize(void);

int64_t NewOnlineDecryptor(const uint8_t *key,
                           size_t key_size,
                           const uint8_t *aad,
                           size_t aad_size,
                           const uint8_t *header,
                           size_t header_size,
                           bool asymmetric,
                           void **output);

int64_t NewOnlineEncryptor(const uint8_t *key,
                           size_t key_size,
                           const uint8_t *aad,
                           size_t aad_size,
                           uint32_t chunk_size,
                           bool asymmetric,
                           uint16_t version,
                           void **output);

int64_t OnlineDecryptorGetChunkSize(const void *ptr);

int64_t OnlineDecryptorGetHeader(const void *ptr, uint8_t *result, size_t result_size);

int64_t OnlineDecryptorGetHeaderSize(const void *ptr);

int64_t OnlineDecryptorGetTagSize(const void *ptr);

int64_t OnlineDecryptorLastChunk(void *ptr,
                                 const uint8_t *data,
                                 size_t data_size,
                                 const uint8_t *aad,
                                 size_t aad_size,
                                 uint8_t *result,
                                 size_t result_size);

int64_t OnlineDecryptorNextChunk(void *ptr,
                                 const uint8_t *data,
                                 size_t data_size,
                                 const uint8_t *aad,
                                 size_t aad_size,
                                 uint8_t *result,
                                 size_t result_size);

int64_t OnlineEncryptorGetChunkSize(const void *ptr);

int64_t OnlineEncryptorGetHeader(const void *ptr, uint8_t *result, size_t result_size);

int64_t OnlineEncryptorGetHeaderSize(const void *ptr);

int64_t OnlineEncryptorGetTagSize(const void *ptr);

int64_t OnlineEncryptorLastChunk(void *ptr,
                                 const uint8_t *data,
                                 size_t data_size,
                                 const uint8_t *aad,
                                 size_t aad_size,
                                 uint8_t *result,
                                 size_t result_size);

int64_t OnlineEncryptorNextChunk(void *ptr,
                                 const uint8_t *data,
                                 size_t data_size,
                                 const uint8_t *aad,
                                 size_t aad_size,
                                 uint8_t *result,
                                 size_t result_size);

/**
 * This is binded here for one specific use case, do not use it if you don't know what you're doing.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t ScryptSimple(const uint8_t *password,
                     size_t password_length,
                     const uint8_t *salt,
                     size_t salt_length,
                     uint8_t log_n,
                     uint32_t r,
                     uint32_t p,
                     uint8_t *output,
                     size_t output_length);

/**
 * This is binded here for one specific use case, do not use it if you don't know what you're doing.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t ScryptSimpleSize(void);

/**
 * Sign data using a keypair to certify its authenticity.
 * # Arguments
 *  * `data` - Pointer to the data to sign.
 *  * `data_length` - Length of the data to sign.
 *  * `keypair` - pointer to the keypair to use to sign the data.
 *  * `keypair_length` - Length of the keypair to use to sign the data.
 *  * `result` - Pointer to the buffer to write the signature to.
 *  * `result_length` - Length of the buffer to write the signature to. You can get the value by
 *                         calling SignSize() beforehand.
 * # Returns
 * This returns 0 if the operation worked. If there is an error, it will return the
 *     appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t Sign(const uint8_t *data,
             size_t data_length,
             const uint8_t *keypair,
             size_t keypair_length,
             uint8_t *result,
             size_t result_length,
             uint16_t version);

/**
 * Get the size of the resulting signature.
 * # Returns
 * Returns the length of the signature to input as `result_length` in `Sign()`.
 */
int64_t SignSize(uint16_t _version);

/**
 * Validate if the header of the data is valid and consistant.
 * # Arguments
 *  * `data` - Pointer to the input buffer.
 *  * `data_length` - Length of the input buffer.
 *  * `data_type` - Type of the data.
 * # Returns
 * 1 if the header is valid, 0 if it's not, and a negative value if there is an error.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t ValidateHeader(const uint8_t *data,
                       size_t data_length,
                       uint16_t data_type);

/**
 * Verify a password against a hash with constant-time equality.
 * # Arguments
 *  * `password` - Pointer to the password to verify.
 *  * `password_length` - Length of the password to verify.
 *  * `hash` - Pointer to the hash to verify.
 *  * `hash_length` - Length of the hash to verify.
 * # Returns
 * Returns 0 if the password is invalid or 1 if the password is valid. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t VerifyPassword(const uint8_t *password,
                       size_t password_length,
                       const uint8_t *hash,
                       size_t hash_length);

/**
 * Verify some data using a signature and the corresponding public key.
 * # Arguments
 *  * `data` - Pointer to the data to verify.
 *  * `data_length` - Length of the data to verify.
 *  * `public_key` - Pointer to the public part of the keypair that was used to sign the data.
 *  * `public_key` - Length of the public part of the keypair that was used to sign the data.
 *  * `signature` - Pointer to the signature to verify.
 *  * `signature_length` - Length of the signature to verify.
 * # Returns
 * Returns 0 if the data, the signature or the public key is invalid or 1 if everything is valid. If there is an error,
 *     it will return the appropriate error code defined in DevoCryptoError.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t VerifySignature(const uint8_t *data,
                        size_t data_length,
                        const uint8_t *public_key,
                        size_t public_key_length,
                        const uint8_t *signature,
                        size_t signature_length);

/**
 *  Fill the output buffer with the version string
 * # Arguments
 *  * output - Pointer to the output buffer.
 *  * output_length - Length of the output buffer.
 * # Returns
 * Returns the size, in bytes, of the output buffer.
 * # Safety
 * This method is made to be called by C, so it is therefore unsafe. The caller should make sure it passes the right pointers and sizes.
 */
int64_t Version(uint8_t *output,
                size_t output_length);

/**
 *  Size of the version string
 * # Returns
 * Returns the size of the version string
 */
int64_t VersionSize(void);
