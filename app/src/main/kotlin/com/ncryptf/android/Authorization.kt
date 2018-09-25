package com.ncryptf.android

import java.lang.IllegalArgumentException
import java.io.UnsupportedEncodingException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import org.threeten.bp.ZoneOffset
import org.threeten.bp.ZonedDateTime
import org.threeten.bp.format.DateTimeFormatter
import android.util.Base64

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid
import com.ncryptf.android.exceptions.KeyDerivationException

import at.favre.lib.crypto.HKDF

/**
 * Generates an signed & versioned Authorization HTTP header from a generate [Signature]
 *
 * @constructor         Generates a versioned Authorization HTTP header
 * @param httpMethod    The HTTP method
 * @param uri           The URI with query string parameters
 * @param token         A Token object
 * @param date          A ZonedDateTime object
 * @param payload       String payload
 * @param version       The version to generate
 * @param salt          Optional 32 byte fixed salt value
 */
public class Authorization constructor(
        private val httpMethod: String,
        private val uri: String,
        private val token: Token,
        private val date: ZonedDateTime,
        private val payload: String,
        private val version: Int = 2,
        private var salt: ByteArray?
    )
{
    companion object {
        /**
        * Default AUTH_INFO "HMAC|AuthenticationKey"
        */
        const val AUTH_INFO = "HMAC|AuthenticationKey"
    }

    /**
     * Generated signature string
     */
    private var signature: String

    /**
     * Generated HMAC
     */
    private var hmac: ByteArray

    /**
     * Libsodium implementation
     */
    private val sodium: LazySodiumAndroid

    /**
     * Primary constructor
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The URI with query string parameters
     * @param token         A Token object
     * @param date          A ZonedDateTime object
     * @param payload       String payload
     * @throws KeyDerivationException
     */
    constructor(
        httpMethod: String,
        uri: String,
        token: Token,
        date: ZonedDateTime,
        payload: String
    ) : this(httpMethod, uri, token, date, payload, 2)

    /**
     * Versioned constructor
     * 
     * @param httpMethod    The HTTP method
     * @param uri           The URI with query string parameters
     * @param token         A Token object
     * @param date          A ZonedDateTime object
     * @param payload       String payload
     * @param version       The version to generate
     * @throws [KeyDerivationException]
     */
    constructor(
        httpMethod: String,
        uri: String,
        token: Token,
        date: ZonedDateTime,
        payload: String,
        version: Int = 2
    ) : this(httpMethod, uri, token, date, payload, version, null)

    init {
        this.sodium = LazySodiumAndroid(SodiumAndroid())
        val method: String = this.httpMethod.toUpperCase()
        if (this.salt == null) {
            this.salt = this.sodium.randomBytesBuf(32)
        }

        if (this.salt?.size != 32) {
            throw IllegalArgumentException()
        }

        this.signature = Signature.derive(
            method,
            this.uri,
            this.salt as ByteArray,
            this.date,
            this.payload,
            version
        )
        
        val hkdf: ByteArray = HKDF.fromHmacSha256().expand(
            HKDF.fromHmacSha256().extract(this.salt as ByteArray, this.token.ikm),
            Authorization.AUTH_INFO.toByteArray(),
            32
        )

        try {
            val hkdfString: String = this.sodium.toHexStr(hkdf).toUpperCase()
            val key: ByteArray = hkdfString.toLowerCase().toByteArray()
            val sig: ByteArray = this.signature.toByteArray()

            val HMAC: Mac = Mac.getInstance("HMACSHA256")
            val secretKey: SecretKeySpec = SecretKeySpec(key, "HMACSHA256")
            
            HMAC.init(secretKey)
            this.hmac = HMAC.doFinal(sig)
        } catch (e: NoSuchAlgorithmException) {
            throw KeyDerivationException("")
        } catch (e: InvalidKeyException) {
            throw KeyDerivationException("")
        } catch (e: UnsupportedEncodingException) {
            throw KeyDerivationException("")
        }
    }

    /**
     * Returns the ZonedDateTime generated or used
     * @return ZonedDateTime
     */
    public fun getDate(): ZonedDateTime
    {
        return this.date
    }

    /**
     * Returns the RFC 2822 formatted date
     * @return String
     */
    public fun getDateString(): String
    {
        return DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss Z")
            .format(this.date).replace(" GMT", " +0000")
    }

    /**
     * Returns the calculated HMAC
     * @return ByteArray
     */
    public fun getHMAC(): ByteArray
    {
        return this.hmac
    }

    /**
     * Returns the base64 encoded HMAC
     * @return String
     */
    public fun getEncodedHMAC(): String
    {
        return Base64.encodeToString(this.hmac, Base64.DEFAULT or Base64.NO_WRAP)
    }

    /**
     * Returns the base64 encoded salt
     * @return String
     */
    public fun getEncodedSalt(): String
    {
        return Base64.encodeToString(this.salt, Base64.DEFAULT or Base64.NO_WRAP)
    }

    /**
     * Returns the generated [Signature] string
     * @return String
     */
    public fun getSignatureString(): String
    {
        return this.signature
    }

    /**
     * Returns the versioned header string
     * @return String
     */
    public fun getHeader(): String?
    {
        val salt: String = this.getEncodedSalt()
        val hmac: String = this.getEncodedHMAC()

        if (this.version == 2) {
            var json: String = "{\"access_token\":\"" + this.token.accessToken + "\",\"date\":\"" + this.getDateString() + "\",\"hmac\":\"" + hmac +"\",\"salt\":\"" + salt + "\",\"v\":2}"
            json = json.replace("/", "\\/")

            val b64: String = Base64.encodeToString(json.toByteArray(), Base64.DEFAULT or Base64.NO_WRAP)
            return "HMAC " + b64
        }

        return "HMAC " + this.token.accessToken + "," + hmac + "," + salt
    }

    /**
     * Validates a provided HMAC against an auth object and a drift
     *
     * @param hmac              32 byte HMAC
     * @param auth              Authorization object generated from HTTP request
     * @param driftAllowance    Number of seconds that the request may be permitted to drift bt
     * @return boolean
     */
     public fun verify(hmac: ByteArray, auth: Authorization, driftAllowance: Int = 90): Boolean
     {
         val drift: Int = this.getTimeDrift(auth.getDate())
         if (drift >= driftAllowance) {
             return false
         }

        if (this.sodium.getSodium().sodium_memcmp(hmac, auth.getHMAC(), 32) == 0) {
            return true
        }

        return false
     }

    /**
     * Calculates the time difference between now and the provided date
     * @param date      The date to compare against
     * @return Int
     */
    private fun getTimeDrift(date: ZonedDateTime): Int
    {
        val now: ZonedDateTime = ZonedDateTime.now(ZoneOffset.UTC)

        return Math.abs(now.toEpochSecond() - date.toEpochSecond()).toInt()
    }
}