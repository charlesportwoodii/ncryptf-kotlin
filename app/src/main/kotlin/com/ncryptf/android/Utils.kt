package com.ncryptf.android

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.exceptions.SodiumException
import com.goterl.lazycode.lazysodium.interfaces.Box
import com.goterl.lazycode.lazysodium.interfaces.Sign

import com.ncryptf.android.Keypair

/**
 * Helper utilities
 */
public class Utils
{
    companion object {
        /**
         * Zeros memory at the given ByteArray range
         * Returns true if memory could be securely zeroed
         * @param data
         * @return Boolean
         */
        @JvmStatic
        public fun zero(data: ByteArray) : Boolean
        {
            val sodium = LazySodiumAndroid(SodiumAndroid())
            sodium.getSodium().sodium_memzero(data, data.size)
            for (i in 0 until data.size) {
                if (data[i].toInt().equals(0).not()) {
                    return false
                }
            }
            return true
        }

        /**
         * Returns a crypto box keypair (32 byte secret, 32 byte public)
         * @return com.ncryptf.android.Keypair
         */
        @JvmStatic
        public fun generateKeypair() : Keypair
        {
            try {
                val sodium = LazySodiumAndroid(SodiumAndroid())
                val box: Box.Lazy = sodium as Box.Lazy
                val kp = box.cryptoBoxKeypair()

                return com.ncryptf.android.Keypair(kp.getSecretKey().getAsBytes(), kp.getPublicKey().getAsBytes())
            } catch (e: SodiumException) {
                return null!!
            }
        }

        /**
         * Returns a crypto sign keypair (64 byte secret, 32 byte public)
         * @return com.ncryptf.android.Keypair
         */
        @JvmStatic
        public fun generateSigningKeypair() : Keypair
        {
            try {
                val sodium = LazySodiumAndroid(SodiumAndroid())
                val sign: Sign.Lazy = sodium as Sign.Lazy
                val kp = sign.cryptoSignKeypair()

                return com.ncryptf.android.Keypair(kp.getSecretKey().getAsBytes(), kp.getPublicKey().getAsBytes())
            } catch (e: SodiumException) {
                return null!!
            }
        }
    }
}