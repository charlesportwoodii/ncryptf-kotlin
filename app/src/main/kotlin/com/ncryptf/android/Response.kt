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

import org.apache.commons.codec.binary.Hex

/**
 * @constructor Primary constructor to decrypt a response
 * @param secretKey
 */
public class Response constructor(
    private var secretKey: ByteArray
)
{
    /**
     * Libsodium implementation
     */
    private val sodium: LazySodiumAndroid

    /**
     * Keypair
     */
    private var keypair: Keypair? = null

    init {
        this.sodium = LazySodiumAndroid(SodiumAndroid())
    }

    /**
     * Secondary constructor for payloads where the public is known
     * @param secretKey     32 byte secret key
     * @param publicKey     32 byte public key
     */
    constructor(secretKey: ByteArray, publicKey: ByteArray) : this(secretKey)
    {
        this.keypair = Keypair(secretKey, publicKey)
    }

    /**
     * Decrypts a v2 encrypted body
     * 
     * @param response
     * @return Decrypted response as a String
     * @throws DecryptionFailedException
     * @throws InvalidChecksumException
     * @throws InvalidSignatureException
     */
    public fun decrypt(response: ByteArray) : String?
    {
        val nonce = Arrays.copyOfRange(response, 4, 28)
        return this.decrypt(response, nonce)
    }

    /**
     * Decrypts a v1 or a v2 encrypted body
     * @param response
     * @param nonce
     * @return Decrypted response as a string
     * @throws DecryptionFailedException
     * @throws InvalidChecksumException
     * @throws InvalidSignatureException
     */
    public fun decrypt(response: ByteArray, nonce: ByteArray) : String?
    {
        val version: Int = this.getVersion(response)
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
                throw DecryptionFailedException("Message size is too small.")
            }

            val payload: ByteArray = Arrays.copyOfRange(response, 0, response.size - 64)
            val checksum: ByteArray = Arrays.copyOfRange(response, response.size - 64, response.size)

            val gh: GenericHash.Native = sodium as GenericHash.Native
            var calculatedChecksum: ByteArray = ByteArray(64)
            if (!gh.cryptoGenericHash(calculatedChecksum, 64, payload, payload.size.toLong(), nonce, nonce.size)) {
                throw DecryptionFailedException("Unable to calculate checksum for message.");
            }

            // If the checksum is invalid, throw an exception
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw InvalidChecksumException("The checksum associated with the message is not valid.");
            }

            val publicKey: ByteArray = Arrays.copyOfRange(response, 28, 60)
            val signature: ByteArray =  Arrays.copyOfRange(payload, payload.size - 64, payload.size)
            val sigPubKey: ByteArray = Arrays.copyOfRange(payload, payload.size - 96, payload.size - 64)
            val body: ByteArray = Arrays.copyOfRange(payload, 60, payload.size - 96)

            this.keypair = Keypair(this.secretKey, publicKey)

            val decryptedPayload = this.decryptBody(body, nonce)
            if (decryptedPayload == null) {
                throw DecryptionFailedException("Failed to decrypt message.")
            }

            try {
                if (!this.isSignatureValid(decryptedPayload as String, signature, sigPubKey)) {
                    throw InvalidSignatureException("The signature associated to the message is not valid.")
                }
            } catch (e: SignatureVerificationException) {
                throw InvalidSignatureException("The signature associated to the message is not valid.")
            }

            return decryptedPayload as String
        }

        return this.decryptBody(response, nonce)
    }

    /**
     * Decrypts the raw response
     * 
     * @param response  Raw byte array response from the server
     * @param nonce     24 byte nonce sent by the server
     * @return          Returns the decrypted payload as a string
     * @throws DecryptionFailedException
     */
    private fun decryptBody(response: ByteArray, nonce: ByteArray) : String?
    {
        val box: Box.Native = sodium as Box.Native
        if (response.size < Box.MACBYTES) {
            throw DecryptionFailedException("Message size is too short.")
        }

        var message: ByteArray = ByteArray(response.size - Box.MACBYTES)

        if (this.keypair == null) {
            throw DecryptionFailedException("Unable to decrypt message with provided keys.")
        }

        val kp = this.keypair as Keypair

        val result: Boolean = box.cryptoBoxOpenEasy(
            message,
            response,
            response.size.toLong(),
            nonce,
            kp.publicKey,
            kp.secretKey
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
        val sign: Sign.Native = sodium as Sign.Native
        val message: ByteArray = response.toByteArray()

        return sign.cryptoSignVerifyDetached(
            signature,
            message,
            message.size.toLong(),
            publicKey
        )
    }

    /**
     * Returns the version from the response
     * 
     * @param response
     * @return int
     * @throws DecryptionFailedException
     */
    private fun getVersion(response: ByteArray) : Int
    {
        // There should be at least 16 MACBYTES for each message.
        // It not present, throw an exception and give up
        if (response.size < 16) {
            throw DecryptionFailedException("Message length is too short to determine version.")
        }

        val header: ByteArray = Arrays.copyOfRange(response, 0, 4)
        val hex: String = String(Hex.encodeHex(header)).toUpperCase()

        if (hex.equals("DE259002")) {
            return 2
        }

        return 1
    }
}