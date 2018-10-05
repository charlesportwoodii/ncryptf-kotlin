package com.ncryptf.android

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.UnsupportedEncodingException

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.goterl.lazycode.lazysodium.interfaces.Box
import com.goterl.lazycode.lazysodium.interfaces.GenericHash
import com.goterl.lazycode.lazysodium.interfaces.Sign

import org.apache.commons.codec.binary.Hex

import com.ncryptf.android.exceptions.EncryptionFailedException
import com.ncryptf.android.exceptions.SigningException

/**
 * @constructor Encrypts a request
 * @param secretKey     32 byte secret key
 * @param publicKey     32 byte public key
 */
public class Request constructor(
    private val secretKey: ByteArray,
    private val signatureSecretKey: ByteArray
)
{
    /**
     * Libsodium implementation
     */
    private val sodium: LazySodiumAndroid

    /**
     * 24 byte nonce
     */
    private var nonce: ByteArray? = null

    init {
        this.sodium = LazySodiumAndroid(SodiumAndroid())
        
        if (this.secretKey.size != Box.SECRETKEYBYTES) {
            throw IllegalArgumentException(String.format("Secret key should be %d bytes", Box.SECRETKEYBYTES))
        }

        if (this.signatureSecretKey.size != Sign.SECRETKEYBYTES) {
            throw IllegalArgumentException(String.format("Secret key should be %d bytes", Sign.SECRETKEYBYTES))
        }
    }

    /**
     * Encrypts the payload
     * 
     * @param data          String payload to encrypt
     * @param publicKey  32 byte signing key
     * @return              Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public fun encrypt(data: String, publicKey: ByteArray) : ByteArray?
    {
        val nonce: ByteArray = this.sodium.randomBytesBuf(Box.NONCEBYTES)
        return encrypt(data, publicKey, 2, nonce)
    }

    /**
     * Encrypts the payload with a specified version, and a generated nonce
     * 
     * @param data              String payload to encrypt
     * @param publicKey   32 byte signing key
     * @param version           Version to generate
     * @return                  Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public fun encrypt(data: String, publicKey: ByteArray, version: Int = 2) : ByteArray?
    {
        val nonce: ByteArray = this.sodium.randomBytesBuf(Box.NONCEBYTES)
        return encrypt(data, publicKey, version, nonce)
    }

    /**
     * Encrypts the payload with a specified version and optional nonce
     * 
     * @param data              String payload to encrypt
     * @param publicKey   32 byte signing key
     * @param version           Version to generate
     * @param nonce             24 byte
     * @return                  Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public fun encrypt(data: String, publicKey: ByteArray, version: Int = 2, nonce: ByteArray) : ByteArray?
    {
        if (nonce.size != Box.NONCEBYTES) {
            throw IllegalArgumentException(String.format("Nonce should be %d bytes", Box.NONCEBYTES))
        }

        this.nonce = nonce

        if (publicKey.size != Box.PUBLICKEYBYTES) {
            throw IllegalArgumentException(String.format("Public key should be %d bytes", Box.PUBLICKEYBYTES))
        }

        if (version == 2) {
            val header: ByteArray = this.sodium.toBinary("DE259002")
            val body = this.encryptBody(data, publicKey, nonce)
            if (body == null) {
                throw EncryptionFailedException("Failed to encrypt message.")
            }

            var iPublicKey: ByteArray = ByteArray(32)

            if (this.sodium.getSodium().crypto_scalarmult_base(iPublicKey, this.secretKey) != 0) {
                throw EncryptionFailedException("Unable to derive public key from the provided secret key.");
            }

            var sigPubKey: ByteArray = ByteArray(32)
            if (this.sodium.getSodium().crypto_sign_ed25519_sk_to_pk(sigPubKey, this.signatureSecretKey) != 0) {
                throw EncryptionFailedException("Unable to derive public key from the provided signature secret key.");
            }

            try {
                val signature = this.sign(data)
                if (signature == null) {
                    throw EncryptionFailedException("Unable to derive signature.")
                }

                var stream: ByteArrayOutputStream = ByteArrayOutputStream()
                stream.write(header)
                stream.write(nonce)
                stream.write(iPublicKey)
                stream.write(body)
                stream.write(sigPubKey)
                stream.write(signature)

                val payload: ByteArray = stream.toByteArray()

                val gh: GenericHash.Native = this.sodium

                var checksum: ByteArray = ByteArray(64)
                if (!gh.cryptoGenericHash(checksum, 64, payload, payload.size.toLong(), nonce, nonce.size)) {
                    throw EncryptionFailedException("Unable to calculate checksum")
                }

                stream.write(checksum)

                return stream.toByteArray()
            } catch (e: SigningException) {
                throw EncryptionFailedException("An unexpected error occurred when encrypting the message.")
            } catch (e: IOException) {
                throw EncryptionFailedException("An unexpected error occurred when encrypting the message.")
            }
        }

        return encryptBody(data, publicKey, nonce)
    }

    /**
     * Encrypts the payload
     * 
     * @param data              String payload to encrypt
     * @param nonce             24 byte nonce
     * @param publicKey   32 byte public key
     * @return                  Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    private fun encryptBody(data: String, publicKey: ByteArray, nonce: ByteArray) : ByteArray?
    {
        if (publicKey.size != Box.PUBLICKEYBYTES) {
            throw IllegalArgumentException(String.format("Public key should be %d bytes", Box.PUBLICKEYBYTES))
        }

        if (nonce.size != Box.NONCEBYTES) {
            throw IllegalArgumentException(String.format("Nonce should be %d bytes", Box.NONCEBYTES))
        }

        val box: Box.Native = this.sodium
        val message: ByteArray = data.toByteArray()
        var cipher: ByteArray = ByteArray(Box.MACBYTES + message.size)

        val result: Boolean = box.cryptoBoxEasy(
            cipher,
            message,
            message.size.toLong(),
            nonce,
            publicKey,
            this.secretKey
        )

        if (result) {
            return cipher
        }

        return null
    }

    /**
     * Encrypts the payload
     * 
     * @param data  String payload to encrypt
     * @return      Byte array containing the encrypted data
     * @throws EncryptionFailedException
     */
    public fun sign(data: String) : ByteArray?
    {
        val message: ByteArray = data.toByteArray()
        var signature: ByteArray = ByteArray(Sign.BYTES)
        val sign: Sign.Native = this.sodium

        val result: Boolean = sign.cryptoSignDetached(
            signature,
            null,
            message,
            message.size.toLong(),
            this.signatureSecretKey
        )

        if (result) {
            return signature
        }

        return null
    }

    /**
     * Returns the 24 byte nonces used for encryption
     * @return ByteArray
     */
    public fun getNonce(): ByteArray
    {
        return this.nonce as ByteArray
    }
}