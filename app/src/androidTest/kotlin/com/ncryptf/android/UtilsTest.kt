import com.goterl.lazycode.lazysodium.LazySodiumAndroid
import com.goterl.lazycode.lazysodium.SodiumAndroid

import org.junit.Test

import org.junit.Assert.*

import com.ncryptf.android.Utils
import com.ncryptf.android.Keypair

class UtilsTest
{
    @Test
    fun testKeypairGeneration()
    {
        val kp: Keypair = Utils.generateKeypair()
        assertEquals(32, kp.publicKey.size)
        assertEquals(32, kp.secretKey.size)
    }

    @Test
    fun testSigningKeypairGeneration()
    {
        val kp: Keypair = Utils.generateSigningKeypair()
        assertEquals(32, kp.publicKey.size)
        assertEquals(64, kp.secretKey.size)
    }

    @Test
    fun testZero()
    {
        val sodium = LazySodiumAndroid(SodiumAndroid())
        var data = sodium.randomBytesBuf(32)

        val zero = Utils.zero(data)

        for (i in 0 until data.size) {
            assertEquals(0, data[i].toInt())
        }

        assertEquals(true, zero)
    }
}