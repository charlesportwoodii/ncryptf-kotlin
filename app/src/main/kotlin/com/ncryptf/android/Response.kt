package com.ncryptf.android

import java.io.UnsupportedEncodingException
import java.util.Arrays

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.Box
import com.goterl.lazycode.lazysodium.interfaces.GenericHash
import com.goterl.lazycode.lazysodium.interfaces.Sign

import com.ncryptf.android.exceptions.DecryptionFailedException
import com.ncryptf.android.exceptions.InvalidChecksumException
import com.ncryptf.android.exceptions.InvalidSignatureException
import com.ncryptf.android.exceptions.SignatureVerificationException

/**
 * @constructor Primary constructor to decrypt a response
 * @param secretKey
 */
public class Response constructor(
    private val secretKey: ByteArray
)
{
    /**
     * Libsodium implementation
     */
    private val sodium: LazySodiumAndroid

    init {
        this.sodium = LazySodiumAndroid(SodiumAndroid())

        if (this.secretKey.size != Box.SECRETKEYBYTES) {
            throw IllegalArgumentException(String.format("Secret key should be %d bytes", Box.SECRETKEYBYTES))
        }
    }

    /**
     * Decrypts a v2 encrypted body
     * 
     * @param response      Byte data returned by the server
     * @return              Decrypted response as a String
     * @throws DecryptionFailedException If the message could not be decrypted
     * @throws InvalidChecksumException If the checksum generated from the message doesn't match the checksum associated with the message
     * @throws InvalidSignatureException If the signature check fails
     * @throws IllegalArgumentException If the response length is too short
     */
    public fun decrypt(response: ByteArray) : String?
    {
        return this.decrypt(response, null)
    }

    /**
     * Decrypts a v2 encrypted body
     * 
     * @param response      Byte data returned by the server
     * @param publicKey     32 byte public key
     * @return              Decrypted response as a String
     * @throws DecryptionFailedException If the message could not be decrypted
     * @throws InvalidChecksumException If the checksum generated from the message doesn't match the checksum associated with the message
     * @throws InvalidSignatureException If the signature check fails
     * @throws IllegalArgumentException If the response length is too short
     */
    public fun decrypt(response: ByteArray, publicKey: ByteArray?) : String?
    {
        if (response.size < 236) {
            throw IllegalArgumentException("Message size is too small.")
        }

        val nonce = Arrays.copyOfRange(response, 4, 28)
        return this.decrypt(response, publicKey, nonce)
    }

    /**
     * Decrypts a v1 or a v2 encrypted body
     * @param response      Byte data returned by the server
     * @param publicKey     32 byte public key
     * @param nonce         24 byte nonce
     * @return              Decrypted response as a string
     * @throws DecryptionFailedException If the message could not be decrypted
     * @throws InvalidChecksumException If the checksum generated from the message doesn't match the checksum associated with the message
     * @throws InvalidSignatureException If the signature check fails
     * @throws IllegalArgumentException If the response length is too short
     */
    public fun decrypt(response: ByteArray, publicKey: ByteArray?, nonce: ByteArray) : String?
    {
        val version: Int = Response.getVersion(response)

        if (nonce.size != Box.NONCEBYTES) {
            throw IllegalArgumentException(String.format("Nonce should be %d bytes", Box.NONCEBYTES))
        }
        
        if (version == 2) {
            /**
             * Payload should be a minimum of 236 bytes
             * 4 byte header
             * 24 byte nonce
             * 32 byte public key
             * 16 byte Box.MACBYTES
             * 32 byte signature public key
             * 64 byte signature
             * 64 byte checksum
             */
            if (response.size < 236) {
                throw IllegalArgumentException("Message size is too small.")
            }

            val payload: ByteArray = Arrays.copyOfRange(response, 0, response.size - 64)
            val checksum: ByteArray = Arrays.copyOfRange(response, response.size - 64, response.size)

            val gh: GenericHash.Native = this.sodium
            var calculatedChecksum: ByteArray = ByteArray(64)
            if (!gh.cryptoGenericHash(calculatedChecksum, 64, payload, payload.size.toLong(), nonce, nonce.size)) {
                throw DecryptionFailedException("Unable to calculate checksum for message.");
            }

            // If the checksum is invalid, throw an exception
            if (this.sodium.getSodium().sodium_memcmp(checksum, calculatedChecksum, 64) != 0) {
                throw InvalidChecksumException("The checksum associated with the message is not valid.");
            }

            val extractedPublicKey: ByteArray = Arrays.copyOfRange(response, 28, 60)
            val signature: ByteArray =  Arrays.copyOfRange(payload, payload.size - 64, payload.size)
            val sigPubKey: ByteArray = Arrays.copyOfRange(payload, payload.size - 96, payload.size - 64)
            val body: ByteArray = Arrays.copyOfRange(payload, 60, payload.size - 96)

            val decryptedPayload = this.decryptBody(body, extractedPublicKey, nonce)
            if (decryptedPayload == null) {
                throw DecryptionFailedException("Failed to decrypt message.")
            }

            try {
                if (!this.isSignatureValid(decryptedPayload, signature, sigPubKey)) {
                    throw InvalidSignatureException("The signature associated to the message is not valid.")
                }
            } catch (e: SignatureVerificationException) {
                throw InvalidSignatureException("The signature associated to the message is not valid.")
            }

            return decryptedPayload
        }

        if (publicKey?.size != Box.PUBLICKEYBYTES) {
            throw IllegalArgumentException(String.format("Public key should be %d bytes", Box.PUBLICKEYBYTES))
        }

        return this.decryptBody(response, publicKey, nonce)
    }

    /**
     * Decrypts the raw response
     * 
     * @param response  Raw byte array response from the server
     * @param publicKey 32 byte public key
     * @param nonce     24 byte nonce sent by the server
     * @return          Returns the decrypted payload as a string
     * @throws DecryptionFailedException If the message could not be decrypted
     */
    private fun decryptBody(response: ByteArray, publicKey: ByteArray, nonce: ByteArray) : String?
    {
        val box: Box.Native = this.sodium

        if (publicKey.size != Box.PUBLICKEYBYTES) {
            throw IllegalArgumentException(String.format("Public key should be %d bytes", Box.PUBLICKEYBYTES))
        }

        if (nonce.size != Box.NONCEBYTES) {
            throw IllegalArgumentException(String.format("Nonce should be %d bytes", Box.NONCEBYTES))
        }

        if (response.size < Box.MACBYTES) {
            throw IllegalArgumentException("Message size is too short.")
        }

        var message: ByteArray = ByteArray(response.size - Box.MACBYTES)

        val result: Boolean = box.cryptoBoxOpenEasy(
            message,
            response,
            response.size.toLong(),
            nonce,
            publicKey,
            this.secretKey
        )

        if (result) {
            return String(message)
        }

        return null
    }

    /**
     * Returns true if the detached signature is valid
     * 
     * @param response  The decrypted response to verify
     * @param signature 64 byte signature
     * @param publicKey 32 byte public key of the signature
     * @return          `true` if the signature is valid, false otherwise
     * @throws SignatureVerificationException
     */
    public fun isSignatureValid(response: String, signature: ByteArray, publicKey: ByteArray) : Boolean
    {
        if (signature.size != 64) {
            throw IllegalArgumentException(String.format("Signature should be %d bytes", 64))
        }

        if (publicKey.size != Sign.PUBLICKEYBYTES) {
            throw IllegalArgumentException(String.format("Public key should be %d bytes", Sign.PUBLICKEYBYTES))
        }

        val sign: Sign.Native = this.sodium
        val message: ByteArray = response.toByteArray()

        return sign.cryptoSignVerifyDetached(
            signature,
            message,
            message.size.toLong(),
            publicKey
        )
    }

    companion object {
        /**
         * Extracts the public key from a v2 response
         * @param response  Response bytes
         * @return          32 byte public key
         * @throws IllegalArgumentException If the response length is too short, or a version 1 message was passed
         */
        @JvmStatic
        public fun getPublicKeyFromResponse(response: ByteArray) : ByteArray
        {
            val version: Int = Response.getVersion(response)
            if (version == 2) {
                if (response.size < 236) {
                    throw IllegalArgumentException(String.format("Expected at least 236 bytes, got %d bytes", response.size))
                }

                return Arrays.copyOfRange(response, 28, 60)
            }

            throw IllegalArgumentException("The response provided is not suitable for public key extraction")
        }

        /**
        * Returns the version from the response
        * 
        * @param response  Response bytes
        * @return int      The version
        * @throws IllegalArgumentException If the response length is too short.
        */
        @JvmStatic
        public fun getVersion(response: ByteArray) : Int
        {
            val sodium: LazySodiumAndroid = LazySodiumAndroid(SodiumAndroid())
            // There should be at least 16 MACBYTES for each message.
            // It not present, throw an exception and give up
            if (response.size < Box.MACBYTES) {
                throw IllegalArgumentException("Message length is too short to determine version.")
            }

            val header: ByteArray = Arrays.copyOfRange(response, 0, 4)
            val hex: String = sodium.toHexStr(header).toUpperCase()

            if (hex.equals("DE259002")) {
                return 2
            }

            return 1
        }
    }
}