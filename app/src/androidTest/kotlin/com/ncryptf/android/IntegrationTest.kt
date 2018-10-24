package com.ncryptf.android.Test

import com.ncryptf.android.Test.Tls12SocketFactory

import android.util.Base64
import android.util.Log
import android.support.test.InstrumentationRegistry
import android.os.Build

import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okhttp3.Request.Builder
import okhttp3.Request
import okhttp3.Response
import okhttp3.ConnectionSpec
import okhttp3.CipherSuite
import okhttp3.TlsVersion

import org.junit.Test
import org.junit.Assert.*
import org.junit.Assume.*

import java.util.Arrays

import com.ncryptf.android.*
import org.json.JSONObject

import org.threeten.bp.ZoneOffset;
import org.threeten.bp.ZonedDateTime;

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid

import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.SSLContext

/**
 * This class demonstrates a practical end-to-end implementation via cURL
 * Implementation may be inferred from this implementation, and is broken out into the following stages:
 * 1. Create a com.ncryptf.android.Keypair instance
 * 2. Bootstrap an encrypted session by sending an unauthenticated requests to the ephemeral key endpoint with the following headers:
 *  - Accept: application/vnd.ncryptf+json
 *  - Content-Type: application/vnd.ncryptf+json
 *  - X-PubKey: <base64_encoded_$key->getPublicKey()>
 * 3. Decrypt the V2 response from the server. This contains a single use ephemeral key we can use to encrypt future requests in the payload.
 *    The servers public key is embedded in the response, and can be extracted by `Response::getPublicKeyFromResponse($response);`
 * 4. Perform an authenticated request using the clients secret key, and the servers public key.
 *
 *
 * Implementation Details
 * - The server WILL always advertise at minimum the following 2 headers:
 *      - X-HashId: A string used to represent the identifier to use to select which key to use.
 *      - X-Public-Key-Expiration: A unix timestamp representing the time at which the key will expire. This is used to determine if rekeying is required.
 * - The server WILL always generate a new keypair for each request. You may continue to use existing keys until they expire.
 * - To achieve perfect-forward-secrecy, it is advised to rekey the client key on each request. The server does not store the shared secret for prior requests.
 * - The client SHOULD keep a record of public keys offered by the server, along with their expiration time.
 * - The client SHOULD always use the most recent key offered by the server.
 * - If the client does not have any active keys, it should bootstrap a new session by calling the ephemeral key endpoint to retrieve a new public key from the server.
 */
public class IntegrationTest
{
    /**
     * This is the URL provided by the `NCRYPTF_TEST_API` environment variable.
     */
    private val url: String

    /**
     * A keypair object
     */
    private val key: Keypair

    /**
     * An optional access token to identify this client.
     */
    private val token: String

    /**
     * Stack containing the public key hash identifier, and original message generated on bootstrap
     * This is a hack to get around the lack of shared states between tests.
     */
    private lateinit var ephemeralKeyBootstrap: JSONObject

    /**
     * Token generated from authenticated
     *This is a hack to get around the lack of shared states between tests.
     */
    private lateinit var authToken: Token

    init {
        val url: String = InstrumentationRegistry.getArguments().getString("NCRYPTF_TEST_API")!!
        val token: String =  InstrumentationRegistry.getArguments().getString("ACCESS_TOKEN")!!

        if (url != "_") {
            this.url = url
        } else {
            this.url = ""
        }

        if (token != "_") {
            this.token = token;
        } else {
            this.token = ""
        }

        this.key = Utils.generateKeypair()!!
    }

    /**
     * Tests the bootstrap process with an encrypted response
     * @return void
     */
    @Test
    fun testEphemeralKeyBootstrap()
    {
        assumeTrue(this.url != "")
        assumeTrue(Build.VERSION.SDK_INT != 19) // Skip SDK 19 for now

        val client: OkHttpClient = OkHttpClient()
        try {
            val builder: Builder = Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/ek")

            if (this.token != "") {
                builder.addHeader("X-Access-Token", this.token)
            }

            val publicKey: String = Base64.encodeToString(this.key.publicKey, Base64.NO_WRAP)
            builder.addHeader("x-pubkey", publicKey)

            val request: okhttp3.Request = builder.build()
            val response: okhttp3.Response = client.newCall(request).execute()

            val r: com.ncryptf.android.Response = com.ncryptf.android.Response(this.key.secretKey)

            assertEquals(200, response.code())

            val responseBody: ByteArray = Base64.decode(response.body()!!.string(), Base64.DEFAULT)
            val message: String = r.decrypt(responseBody)!!
            val json: JSONObject = JSONObject(message)

            assertTrue(!message.isNullOrEmpty())
            assertTrue(!json.getString("public").isNullOrEmpty())
            assertTrue(!json.getString("signature").isNullOrEmpty())
            assertTrue(!json.getString("hash-id").isNullOrEmpty())

            val ekb: JSONObject = JSONObject()
            ekb.put("key", Base64.encodeToString(com.ncryptf.android.Response.getPublicKeyFromResponse(responseBody), Base64.DEFAULT))
            ekb.put("hash-id", response.headers().get("x-hashid"))
            this.ephemeralKeyBootstrap = ekb
        } catch (e: Exception) {
            fail(e.message)
        }
    }

    /**
     * This requests illustrates making an unauthenticated encrypted request and receiving an encrypted response
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    fun testUnauthenticatedEncryptedRequest()
    {
        assumeTrue(this.url != "")
        assumeTrue(Build.VERSION.SDK_INT != 19) // Skip SDK 19 for now

        this.testEphemeralKeyBootstrap()
        val stack: JSONObject = this.ephemeralKeyBootstrap

        val client: OkHttpClient = OkHttpClient()
        try {
            val builder: Builder = Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo")

            if (this.token != "") {
                builder.addHeader("X-Access-Token", this.token)
            }

            builder.addHeader("X-HashId", stack.getString(("hash-id")))

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            //val publicKey: String = Base64.encodeToString(this.key.publicKey, Base64.NO_WRAP)
            //builder.addHeader("x-pubkey", publicKey)

            val payload: String = "{\"hello\":\"world\"}"

            val req: com.ncryptf.android.Request = com.ncryptf.android.Request(
                this.key.secretKey,
                Utils.generateSigningKeypair()!!.secretKey
            )

            val encryptedPayload: String = Base64.encodeToString(
                req.encrypt(payload, Base64.decode(stack.getString("key"), Base64.DEFAULT))!!
            , Base64.DEFAULT)

            builder.post(RequestBody.create(null, encryptedPayload))

            val request: okhttp3.Request = builder.build()
            val response: okhttp3.Response = client.newCall(request).execute()

            val r: com.ncryptf.android.Response = com.ncryptf.android.Response(this.key.secretKey)

            assertEquals(200, response.code())

            val responseBody: ByteArray = Base64.decode(response.body()!!.string(), Base64.DEFAULT)
            val message: String = r.decrypt(responseBody)!!

            assertEquals(payload, message)
        } catch (e: Exception) {
            fail(e.message)
        }
    }

    /**
     * This request securely authenticates a user with an encrypted request and returns an encrypted response
     * This request is encrypted end-to-end
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    fun testAuthenticateWithEncryptedRequest()
    {
        assumeTrue(this.url != "")
        assumeTrue(Build.VERSION.SDK_INT != 19) // Skip SDK 19 for now

        this.testEphemeralKeyBootstrap()
        val stack: JSONObject = this.ephemeralKeyBootstrap

       val client: OkHttpClient = OkHttpClient()
        try {
            val builder: Builder = Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/authenticate")

            if (this.token != "") {
                builder.addHeader("X-Access-Token", this.token)
            }

            builder.addHeader("X-HashId", stack.getString(("hash-id")))

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            //val publicKey: String = Base64.encodeToString(this.key.publicKey, Base64.NO_WRAP)
            //builder.addHeader("x-pubkey", publicKey)

            val payload: String = "{\"email\":\"clara.oswald@example.com\",\"password\":\"c0rect h0rs3 b@tt3y st@Pl3\"}"

            val req: com.ncryptf.android.Request = com.ncryptf.android.Request(
                this.key.secretKey,
                Utils.generateSigningKeypair()!!.secretKey
            )

            val encryptedPayload: String = Base64.encodeToString(
                req.encrypt(payload, Base64.decode(stack.getString("key"), Base64.DEFAULT))!!
            , Base64.DEFAULT)

            builder.post(RequestBody.create(null, encryptedPayload))

            val request: okhttp3.Request = builder.build()
            val response: okhttp3.Response = client.newCall(request).execute()

            val r: com.ncryptf.android.Response = com.ncryptf.android.Response(this.key.secretKey)

            assertEquals(200, response.code())

            val responseBody: ByteArray = Base64.decode(response.body()!!.string(), Base64.DEFAULT)
            val message: String = r.decrypt(responseBody)!!
            val json: JSONObject = JSONObject(message)

            assertTrue(!message.isNullOrEmpty())
            assertTrue(!json.getString("access_token").isNullOrEmpty())
            assertTrue(!json.getString("refresh_token").isNullOrEmpty())
            assertTrue(!json.getString("ikm").isNullOrEmpty())
            assertTrue(!json.getString("signing").isNullOrEmpty())
            assertTrue(json.getInt("expires_at") > 0)

            this.authToken = Token(
                json.getString("access_token"),
                json.getString("refresh_token"),
                Base64.decode(json.getString("ikm"), Base64.DEFAULT),
                Base64.decode(json.getString("signing"), Base64.DEFAULT),
                json.getInt("expires_at").toDouble()
            )
        } catch (e: Exception) {
            fail(e.message)
        }
    }

    /**
     * This request securely authenticates a user with an encrypted request and returns an encrypted response
     * This request is encrypted end-to-end
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    fun tesTauthenticatedEchoWithEncryptedRequest()
    {
        this.testAuthenticateWithEncryptedRequest()
        val stack: JSONObject = this.ephemeralKeyBootstrap
        val token: Token = this.authToken

        val client: OkHttpClient = OkHttpClient()
        try {
            val builder: Builder = Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo")

            if (this.token != "") {
                builder.addHeader("X-Access-Token", this.token)
            }

            builder.addHeader("X-HashId", stack.getString(("hash-id")))

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            //val publicKey: String = Base64.encodeToString(this.key.publicKey, Base64.NO_WRAP)
            //builder.addHeader("x-pubkey", publicKey)

            val payload: String = "{\"hello\":\"world\"}"

            val req: com.ncryptf.android.Request = com.ncryptf.android.Request(
                this.key.secretKey,
                token.signature
            )

            val encryptedPayload: String = Base64.encodeToString(
                req.encrypt(payload, Base64.decode(stack.getString("key"), Base64.DEFAULT))!!
            , Base64.DEFAULT)

            val auth: Authorization = Authorization(
                "PUT",
                "/echo",
                token,
                ZonedDateTime.now((ZoneOffset.UTC)),
                payload
            )

            builder.addHeader("Authorization", auth.getHeader()!!)

            builder.put(RequestBody.create(null, encryptedPayload))

            val request: okhttp3.Request = builder.build()
            val response: okhttp3.Response = client.newCall(request).execute()

            val r: com.ncryptf.android.Response = com.ncryptf.android.Response(this.key.secretKey)

            assertEquals(200, response.code())

            val responseBody: ByteArray = Base64.decode(response.body()!!.string(), Base64.DEFAULT)
            val message: String = r.decrypt(responseBody)!!

            /**
             * As an added integrity check, the API will sign the message with the same key it issued during authentication
             * Therefore, we can verify that the signing public key associated to the message matches the public key from the
             * token we were issued.
             *
             * If the keys match, then we have assurance that the message is authenticated
             * If the keys don't match, then the request has been tampered with and should be discarded.
             *
             * This check should ALWAYS be performed for authenticated requests as it ensures the validity of the message
             * and the origin of the message.
             */
            val sodium: LazySodiumAndroid = LazySodiumAndroid(SodiumAndroid())

            assertTrue(
                sodium.getSodium().sodium_memcmp(
                    token.getSignaturePublicKey(),
                    com.ncryptf.android.Response.getSigningPublicKeyFromResponse(responseBody),
                    32
                ) == 0
            )

            // The echo endpoint should echo the same response back to use after decrypting it.
            assertEquals(payload, message)
        } catch (e: Exception) {
            fail(e.message)
        }
    }

    /************************************************************************************************
     *
     * The requests that follow are for implementation sanity checks, and should not be referenced
     * for other client implementations
     *
     ************************************************************************************************/

    /**
     * De-authenticates a user via an encrypted and authenticated request
     * @depends testAuthenticateWithEncryptedRequest
     * @return void
     */
    @Test
    fun testAuthenticatedEchoWithBadSignature()
    {
        this.testAuthenticateWithEncryptedRequest()
        val stack: JSONObject = this.ephemeralKeyBootstrap
        val token: Token = this.authToken

        val client: OkHttpClient = OkHttpClient()
        try {
            val builder: Builder = Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo")

            if (this.token != "") {
                builder.addHeader("X-Access-Token", this.token)
            }

            builder.addHeader("X-HashId", stack.getString(("hash-id")))

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            //val publicKey: String = Base64.encodeToString(this.key.publicKey, Base64.NO_WRAP)
            //builder.addHeader("x-pubkey", publicKey)

            val payload: String = "{\"hello\":\"world\"}"

            val req: com.ncryptf.android.Request = com.ncryptf.android.Request(
                this.key.secretKey,
                Utils.generateSigningKeypair()!!.secretKey
            )

            val encryptedPayload: String = Base64.encodeToString(
                req.encrypt(payload, Base64.decode(stack.getString("key"), Base64.DEFAULT))!!
            , Base64.DEFAULT)

            val auth: Authorization = Authorization(
                "PUT",
                "/echo",
                token,
                ZonedDateTime.now((ZoneOffset.UTC)),
                payload
            )

            builder.addHeader("Authorization", auth.getHeader()!!)

            builder.put(RequestBody.create(null, encryptedPayload))

            val request: okhttp3.Request = builder.build()
            val response: okhttp3.Response = client.newCall(request).execute()

            assertEquals(401, response.code())
        } catch (e: Exception) {
            fail(e.message)
        }
    }

    /**
     * Verifies that a tampered request results in an error.
     * @depends testEphemeralKeyBootstrap
     * @return void
     */
    @Test
    fun testMalformedEncryptedRequest()
    {
        assumeTrue(this.url != "")
        assumeTrue(Build.VERSION.SDK_INT != 19) // Skip SDK 19 for now

        this.testEphemeralKeyBootstrap()
        val stack: JSONObject = this.ephemeralKeyBootstrap

        val client: OkHttpClient = OkHttpClient()
        try {
            val builder: Builder = Builder()
                .addHeader("Accept", "application/vnd.ncryptf+json")
                .addHeader("Content-Type", "application/vnd.ncryptf+json")
                .url(this.url + "/echo")

            if (this.token != "") {
                builder.addHeader("X-Access-Token", this.token)
            }

            builder.addHeader("X-HashId", stack.getString(("hash-id")))

            // Our public is is embedded in the signed request, so we don't need to explicitly tell
            // the server what our public key is via this header. Implementors may wish to always include this for convenience
            // If a public key is embedded in the body, it will supercede whatever is in the header.
            //val publicKey: String = Base64.encodeToString(this.key.publicKey, Base64.NO_WRAP)
            //builder.addHeader("x-pubkey", publicKey)

            val payload: String = "{\"hello\":\"world\"}"

            val req: com.ncryptf.android.Request = com.ncryptf.android.Request(
                this.key.secretKey,
                Utils.generateSigningKeypair()!!.secretKey
            )

            val rawPayload: ByteArray = req.encrypt(payload, Base64.decode(stack.getString("key"), Base64.DEFAULT))!!
            rawPayload.fill(0x00, 60, 92)

            val encryptedPayload: String = Base64.encodeToString(
                rawPayload
            , Base64.DEFAULT)

            builder.post(RequestBody.create(null, encryptedPayload))

            val request: okhttp3.Request = builder.build()
            val response: okhttp3.Response = client.newCall(request).execute()

            assertEquals(400, response.code())
        } catch (e: Exception) {
            fail(e.message)
        }
    }
}