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
}