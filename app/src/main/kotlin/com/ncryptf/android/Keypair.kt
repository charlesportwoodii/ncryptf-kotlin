package com.ncryptf.android

/**
 * @constructor Instantiates a new keypair with a 32 byte secret and 32 byte public key
 * @param secretKey 32 byte secret key
 * @param publicKey 32 byte public key
 */
public data class Keypair constructor(
    val secretKey: ByteArray,
    val publicKey: ByteArray
)
{
    init {
        if (this.secretKey.size % 16 != 0) {
            throw IllegalArgumentException(String.format("Secret key should be a multiple of %d bytes", 16))
        }

        if (this.publicKey.size % 4 != 0) {
            throw IllegalArgumentException(String.format("Public key should be a multiple of %d bytes", 4))
        }
    }
}