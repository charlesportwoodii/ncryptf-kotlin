package com.ncryptf.android

import java.time.ZonedDateTime
import java.time.ZoneOffset

import com.ncryptf.android.Utils

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
    /**
     * Returns true if the given token is expired, and false otherwise
     * @return Boolean
     */
    public fun isExpired() : Boolean
    {
        val now = ZonedDateTime.now(ZoneOffset.UTC).toEpochSecond()
        return now > this.expiresAt
    }
}