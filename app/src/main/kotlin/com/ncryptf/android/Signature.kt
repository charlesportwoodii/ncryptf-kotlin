package com.ncryptf.android

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.GenericHash

import org.apache.commons.codec.binary.Hex
import org.apache.commons.codec.digest.DigestUtils

public class Signature
{
    companion object {

        @JvmStatic
        public fun derive(httpMethod: String, uri: String, salt: ByteArray, date: ZonedDateTime, payload: String) : String
        {
            return derive(httpMethod, uri, salt, date, payload, 2)
        }

        @JvmStatic
        public fun derive(httpMethod: String, uri: String, salt: ByteArray, date: ZonedDateTime, payload: String, version: Int) : String
        {
            val method = httpMethod.toUpperCase()

            val hash: String = this.getSignatureHash(payload, salt, version)
            val b64Salt: String = String(Base64.getEncoder().encode(salt))
            val timestamp: String = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z").format(date).replace(" GMT", " +0000");

            return hash + "\n" + 
               method + "+" + uri + "\n" +
               timestamp + "\n" +
               b64Salt
        }

        @JvmStatic
        private fun getSignatureHash(data: String, salt: ByteArray, version: Int) : String
        {
            if (version == 2) {
                val sodium = LazySodiumAndroid(SodiumAndroid())
                val gh: GenericHash.Native = sodium as GenericHash.Native
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

                return String(Base64.getEncoder().encode(h))
            }

            return String(Hex.encodeHex(DigestUtils.sha256(data))).toLowerCase()
        }
    }
}
