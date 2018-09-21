package com.ncryptf.android

import java.time.ZonedDateTime
import java.time.ZoneOffset

import com.ncryptf.android.Utils

public data class Token constructor(val accessToken: String, val refreshToken: String, val ikm: ByteArray, val signature: ByteArray, val expiresAt: Double)
{
    public fun isExpired() : Boolean
    {
        val now = ZonedDateTime.now(ZoneOffset.UTC).toEpochSecond()
        return now > this.expiresAt
    }
}