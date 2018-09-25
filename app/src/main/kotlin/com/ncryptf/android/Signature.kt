package com.ncryptf.android

import org.threeten.bp.ZonedDateTime
import org.threeten.bp.format.DateTimeFormatter
import android.util.Base64

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.GenericHash

import org.apache.commons.codec.digest.DigestUtils

/**
 * Generates versioned signature strings for [Authorization]
 */
public class Signature
{
    companion object {
        /**
         * Constructs a new v2 signature
         * 
         * @param httpMethod    The HTTP method
         * @param uri           The full URI with query string parameters
         * @param salt          32 byte salt
         * @param date          ZonedDateTime object
         * @param payload       String request body to sign
         * @return Version 2 signature
         */
        @JvmStatic
        public fun derive(httpMethod: String, uri: String, salt: ByteArray, date: ZonedDateTime, payload: String) : String
        {
            return derive(httpMethod, uri, salt, date, payload, 2)
        }

        /**
         * Constructs versioned signature
         * 
         * @param httpMethod    The HTTP method
         * @param uri           The full URI with query string parameters
         * @param salt          32 byte salt
         * @param date          ZonedDateTime object
         * @param payload       String request body to sign
         * @param version       The integer signature version
         * @return Versioned signatured
         */
        @JvmStatic
        public fun derive(httpMethod: String, uri: String, salt: ByteArray, date: ZonedDateTime, payload: String, version: Int) : String
        {
            val method = httpMethod.toUpperCase()

            val hash: String = this.getSignatureHash(payload, salt, version)
            val b64Salt: String = Base64.encodeToString(salt, Base64.DEFAULT or Base64.NO_WRAP)
            val timestamp: String = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z").format(date).replace(" GMT", " +0000");

            return hash + "\n" + 
               method + "+" + uri + "\n" +
               timestamp + "\n" +
               b64Salt
        }

        /**
         * Returns the signature hash
         * 
         * @param data      The data to hash
         * @param salt      32 byte salt
         * @param version   The signature hash version to generate.
         * @return          A string epresenting the signature hash
         */
        @JvmStatic
        private fun getSignatureHash(data: String, salt: ByteArray, version: Int) : String
        {
            val sodium = LazySodiumAndroid(SodiumAndroid())

            if (version == 2) {
                val gh: GenericHash.Native = sodium
                val h = ByteArray(64)
                val dataBytes = data.toByteArray()
                gh.cryptoGenericHash(
                    h,
                    h.size,
                    dataBytes,
                    dataBytes.size.toLong(),
                    salt,
                    salt.size
                )

                return Base64.encodeToString(h, Base64.DEFAULT or Base64.NO_WRAP)
            }

            return sodium.toHexStr(DigestUtils.sha256(data)).toLowerCase()
        }
    }
}
