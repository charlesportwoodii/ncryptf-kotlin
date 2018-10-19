package com.ncryptf.android.Test

import org.junit.Test
import org.junit.Assert.*
import com.ncryptf.android.Authorization
import com.ncryptf.android.exceptions.KeyDerivationException

import android.util.Base64
import org.json.JSONObject

import org.threeten.bp.ZoneOffset
import org.threeten.bp.ZonedDateTime

public class AuthorizationTest: AbstractTest()
{
    @Test
    fun testV1HMAC()
    {
        var index: Int = 0
        for (test in this.testCases) {
            try {
                val auth: Authorization = Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    this.date,
                    test.payload,
                    1,
                    this.salt
                )

                val header: String = this.v1HMACHeaders[index++]
                assertEquals(header, auth.getHeader())
                val r = header.split(",")
                val hmac: ByteArray = Base64.decode(r[1], Base64.DEFAULT)
                assertEquals(false, auth.verify(hmac, auth, 90))
            } catch (e: KeyDerivationException) {
                fail("KeyDerivationException")
            }
        }
    }

    @Test
    fun testV2HMAC()
    {
        var index: Int = 0
        for (test in this.testCases) {
            try {
                val auth: Authorization = Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    this.date,
                    test.payload,
                    2,
                    this.salt
                )

                val header: String = this.v2HMACHeaders[index++]
                assertEquals(header, auth.getHeader())
                val json = JSONObject(String(Base64.decode(header.replace("HMAC ", ""), Base64.DEFAULT)))
                val hmac: ByteArray = Base64.decode(json.getString("hmac"), Base64.DEFAULT)
                assertEquals(false, auth.verify(hmac, auth, 90))
            } catch (e: KeyDerivationException) {
                fail("KeyDerivationException")
            }
        }
    }

    @Test
    fun testVerify()
    {
        for (test in this.testCases) {
            try {
                val auth: Authorization = Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    ZonedDateTime.now(ZoneOffset.UTC),
                    test.payload,
                    1,
                    this.salt
                )

                assertEquals(true, auth.verify(auth.getHMAC(), auth, 90));

                val auth2: Authorization = Authorization(
                    test.httpMethod,
                    test.uri,
                    this.token,
                    ZonedDateTime.now(ZoneOffset.UTC),
                    test.payload,
                    2,
                    this.salt
                )

                assertEquals(true, auth2.verify(auth2.getHMAC(), auth2, 90));
            } catch (e: KeyDerivationException) {
                fail("KeyDerivationException")
            }
        }
    }
}
