import org.junit.Test
import org.junit.Assert.*
import com.ncryptf.android.Authorization
import com.ncryptf.android.exceptions.KeyDerivationException

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

                assertEquals(this.v1HMACHeaders[index++], auth.getHeader())
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

                assertEquals(this.v2HMACHeaders[index++], auth.getHeader())
            } catch (e: KeyDerivationException) {
                fail("KeyDerivationException")
            }
        }
    }
}
