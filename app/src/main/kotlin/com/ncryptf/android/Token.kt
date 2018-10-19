package com.ncryptf.android

import org.threeten.bp.ZonedDateTime
import org.threeten.bp.ZoneOffset

import com.ncryptf.android.Utils
import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid

/**
 * @constructor Data class for storing token details
 * @param accessToken The access token
 * @param refreshToken The refresh token
 * @param ikm 32 byte initial key material
 * @param signature The signature bytes
 * @param expiresAt The token expiration time
 */
public data class Token constructor(
    val accessToken: String,
    val refreshToken: String,
    val ikm: ByteArray,
    val signature: ByteArray,
    val expiresAt: Double
)
{
    init {
        if (this.ikm.size != 32) {
            throw IllegalArgumentException(String.format("Initial key material should be %d bytes", 32))
        }

        if (this.signature.size != 64) {
            throw IllegalArgumentException(String.format("Signature secret key should be %d bytes", 64))
        }
    }

    /**
     * Returns true if the given token is expired, and false otherwise
     * @return Boolean
     */
    public fun isExpired() : Boolean
    {
        val now = ZonedDateTime.now(ZoneOffset.UTC).toEpochSecond()
        return now > this.expiresAt
    }

    /**
     * Extracts the signature public key from the provided private key
     * @return ByteArray
     */
    public fun getSignaturePublicKey() : ByteArray?
    {
        val sodium: LazySodiumAndroid = LazySodiumAndroid(SodiumAndroid())
        val publicKey: ByteArray = ByteArray(32);
        if (sodium.getSodium().crypto_sign_ed25519_sk_to_pk(publicKey, this.signature) != 0) {
            return null
        }

        return publicKey
    }
}