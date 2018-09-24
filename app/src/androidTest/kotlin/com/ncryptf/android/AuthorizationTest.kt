import org.junit.Test
import org.junit.Assert.*
import com.ncryptf.android.Authorization
import com.ncryptf.android.exceptions.KeyDerivationException

import java.util.Base64;
import org.json.JSONObject;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

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
                val hmac: ByteArray = Base64.getDecoder().decode(r[1])
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
                val json = JSONObject(String(Base64.getDecoder().decode(header.replace("HMAC ", ""))))
                val hmac: ByteArray = Base64.getDecoder().decode(json.getString("hmac"))
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
