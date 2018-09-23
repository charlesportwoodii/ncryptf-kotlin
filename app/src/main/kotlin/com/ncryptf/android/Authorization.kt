package com.ncryptf.android

import java.io.UnsupportedEncodingException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid

import at.favre.lib.crypto.HKDF
import com.ncryptf.android.exceptions.KeyDerivationException
import com.ncryptf.android.Token

/**
 * Generates an signed & versioned Authorization HTTP header from a generate [Signature]
 *
 * @constructor            Generates a versioned Authorization HTTP header
 * @property httpMethod    The HTTP method
 * @property uri           The URI with query string parameters
 * @property token         A Token object
 * @property date          A ZonedDateTime object
 * @property payload       String payload
 * @property version       The version to generate
 * @property salt          Optional 32 byte fixed salt value
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
        version: Int
    ) : this(httpMethod, uri, token, date, payload, version, null)

    init {
        this.sodium = LazySodiumAndroid(SodiumAndroid())
        val method: String = this.httpMethod.toUpperCase()
        if (this.salt == null) {
            this.salt = this.sodium.randomBytesBuf(32)
        }

        this.signature = Signature.derive(
            method,
            this.uri,
            this.salt!!,
            this.date,
            this.payload,
            version
        )

        val hkdf: ByteArray = HKDF.fromHmacSha256().expand(
            HKDF.fromHmacSha256().extract(this.salt, this.token.ikm),
            Authorization.AUTH_INFO.toByteArray(),
            32
        )
        this.hmac = ByteArray(32)
        this.signature = ""
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
        return Base64.getEncoder().encodeToString(this.hmac)
    }

    /**
     * Returns the base64 encoded salt
     * @return String
     */
    public fun getEncodedSalt(): String
    {
        return Base64.getEncoder().encodeToString(this.salt);
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

            val b64: String = Base64.getEncoder().encodeToString(json.toByteArray())
            return "HMAC " + b64;
        }

        return "HMAC " + this.token.accessToken + "," + hmac + "," + salt
    }
}