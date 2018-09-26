package com.ncryptf.android.Test

import org.junit.Test
import org.junit.Assert.*

import android.util.Base64

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid

import com.ncryptf.android.exceptions.*
import com.ncryptf.android.Request
import com.ncryptf.android.Response

public class RequestResponseTest
{
    private val clientKeyPairSecret: ByteArray = Base64.decode("bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=", Base64.DEFAULT)
    private val clientKeyPairPublic: ByteArray = Base64.decode("Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU=", Base64.DEFAULT)
    
    private val serverKeyPairSecret: ByteArray = Base64.decode("gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=", Base64.DEFAULT)
    private val serverKeyPairPublic: ByteArray = Base64.decode("YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8=", Base64.DEFAULT)

    private val signatureKeyPairSecret: ByteArray = Base64.decode("9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==", Base64.DEFAULT)
    private val signatureKeyPairPublic: ByteArray = Base64.decode("IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE=", Base64.DEFAULT)

    private val nonce: ByteArray = Base64.decode("bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut", Base64.DEFAULT)

    private val expectedCipher: ByteArray = Base64.decode("1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=", Base64.DEFAULT)
    private val expectedSignature: ByteArray = Base64.decode("dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==", Base64.DEFAULT)

    private val expectedv2Cipher: ByteArray = Base64.decode("3iWQAm7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLTo569CkMuhiesfnkGvsDcHR3o2aPL2OVTcmWOTX8AY11odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg4SwqYwa53inoY2+eCPP4Hkp/PKhSOEMFlWV+dlQirn6GGf5RQSsQ7ti/QCvi/BRIhb3ZHiPptZJZIbYwqIpvYu", Base64.DEFAULT)

    private val payload: String = """{
    "foo": "bar",
    "test": {
        "true": false,
        "zero": 0.0,
        "a": 1,
        "b": 3.14,
        "nil": null,
        "arr": [
            "a", "b", "c", "d"
        ]
    }
}"""

    private val sodium: LazySodiumAndroid

    init {
        this.sodium = LazySodiumAndroid(SodiumAndroid())
    }
    
    @Test
    fun testv2EncryptDecrypt()
    {
        try {
            val request: Request = Request(
                this.clientKeyPairSecret,
                this.serverKeyPairPublic
            )

            val cipher: ByteArray = request.encrypt(this.payload, this.signatureKeyPairSecret, 2, this.nonce) as ByteArray

            val eCipher: String = this.sodium.toHexStr(this.expectedv2Cipher)
            val aCipher: String = this.sodium.toHexStr(cipher)

            assertEquals(eCipher, aCipher)

            val response: Response = Response(
                this.serverKeyPairSecret
            )

            val decrypted: String = response.decrypt(cipher) as String
            assertEquals(payload, decrypted)
        } catch (e: EncryptionFailedException) {
            fail("Encryption failed")
        } catch (e: DecryptionFailedException) {
            fail("Decryption failed")
        } catch (e: SigningException) {
            fail("Signing failed")
        } catch (e: SignatureVerificationException) {
            fail("Signature verification failed")
        } catch (e: InvalidChecksumException) {
            fail("Checksum is invalid")
        } catch (e: InvalidSignatureException) {
            fail("Signature is invalid")
        }
    }

    @Test
    fun testv2EncryptDecryptWithEmptyPayload()
    {
        try {
            val request: Request = Request(
                this.clientKeyPairSecret,
                this.serverKeyPairPublic
            )

            val cipher: ByteArray = request.encrypt("", this.signatureKeyPairSecret, 2, this.nonce) as ByteArray

            val response: Response = Response(
                this.serverKeyPairSecret
            )

            val decrypted: String = response.decrypt(cipher) as String
            assertEquals("", decrypted)
        } catch (e: EncryptionFailedException) {
            fail("Encryption failed")
        } catch (e: DecryptionFailedException) {
            fail("Decryption failed")
        } catch (e: SigningException) {
            fail("Signing failed")
        } catch (e: SignatureVerificationException) {
            fail("Signature verification failed")
        } catch (e: InvalidChecksumException) {
            fail("Checksum is invalid")
        } catch (e: InvalidSignatureException) {
            fail("Signature is invalid")
        }
    }

    @Test(expected = DecryptionFailedException::class)
    fun testv2DecryptWithSmallPayload()
    {
        // Force v2 by setting the magic header
        val header: ByteArray = this.sodium.toBinary("DE259002")
        val cipher: ByteArray = header + ByteArray(231)

        val response: Response = Response(
            this.serverKeyPairSecret,
            this.clientKeyPairPublic
        )

        response.decrypt(cipher)
    }

    @Test(expected = DecryptionFailedException::class)
    fun testv1DecryptWithSmallPayload()
    {
        val cipher: ByteArray = ByteArray(15)

        val response: Response = Response(
            this.serverKeyPairSecret,
            this.clientKeyPairPublic
        )

        response.decrypt(cipher, this.nonce)
    }
    
    @Test
    fun testv1EncryptDecrypt()
    {
        try {
            val request: Request = Request(
                this.clientKeyPairSecret,
                this.serverKeyPairPublic
            )

            val cipher: ByteArray = request.encrypt(this.payload, null, 1, this.nonce) as ByteArray
            val signature: ByteArray = request.sign(this.payload, this.signatureKeyPairSecret) as ByteArray

            val response: Response = Response(
                this.serverKeyPairSecret,
                this.clientKeyPairPublic
            )

            val decrypted: String = response.decrypt(cipher, this.nonce) as String

            val eCipher: String = this.sodium.toHexStr(this.expectedCipher)
            val aCipher: String = this.sodium.toHexStr(cipher)

            val eSignature: String = this.sodium.toHexStr(this.expectedSignature)
            val aSignature: String = this.sodium.toHexStr(signature)

            assertEquals(eCipher, aCipher)
            assertEquals(eSignature, aSignature)
            assertEquals(payload, decrypted)

            val isSignatureValid: Boolean = response.isSignatureValid(
                decrypted,
                signature,
                this.signatureKeyPairPublic
            )

            assertTrue(isSignatureValid)
        } catch (e: EncryptionFailedException) {
            fail("Encryption failed")
        } catch (e: DecryptionFailedException) {
            fail("Decryption failed")
        } catch (e: SigningException) {
            fail("Signing failed")
        } catch (e: SignatureVerificationException) {
            fail("Signature verification failed")
        } catch (e: InvalidChecksumException) {
            fail("Checksum is invalid")
        } catch (e: InvalidSignatureException) {
            fail("Signature is invalid")
        }
    }
}