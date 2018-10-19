package com.ncryptf.android.Test

import android.util.Base64
import android.util.Log
import android.support.test.InstrumentationRegistry

import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okhttp3.Request.Builder
import okhttp3.Request
import okhttp3.Response

import org.junit.Test
import org.junit.Assert.*
import org.junit.Assume.*

import java.util.Arrays

import com.ncryptf.android.*
import org.json.JSONObject

import org.threeten.bp.ZonedDateTime

import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid


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
            assertTrue(!json.getString("public").isNullOrEmpty());
            assertTrue(!json.getString("signature").isNullOrEmpty());
            assertTrue(!json.getString("hash-id").isNullOrEmpty());

            val ekb: JSONObject = JSONObject()
            ekb.put("key", Base64.encode(com.ncryptf.android.Response.getPublicKeyFromResponse(responseBody), Base64.DEFAULT))
            ekb.put("hash-id", response.headers().get("x-hashid"))
            this.ephemeralKeyBootstrap = ekb
        } catch (e: Exception) {
            fail(e.message)
        }
    }
}