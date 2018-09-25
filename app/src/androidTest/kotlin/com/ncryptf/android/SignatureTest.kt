import org.junit.Test
import org.junit.Assert.*
import com.ncryptf.android.Signature

import android.util.Base64;
import org.json.JSONObject;

public class SignatureTest: AbstractTest()
{
    @Test
    fun testV1Signatures()
    {
        var index: Int = 0
        for (test in this.testCases) {
            val signature: String = Signature.derive(
                test.httpMethod,
                test.uri,
                this.salt,
                this.date,
                test.payload,
                1
            )

            val lines = signature.lines()
            assertEquals(this.v1SignatureResults[index++], lines[0])
        }
    }

    @Test
    fun testV2Signatures()
    {
        var index: Int = 0
        for (test in this.testCases) {
            val signature: String = Signature.derive(
                test.httpMethod,
                test.uri,
                this.salt,
                this.date,
                test.payload
            )

            val lines = signature.lines()
            assertEquals(this.v2SignatureResults[index++], lines[0])
        }
    }
}
