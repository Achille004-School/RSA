package rsa

import java.math.BigInteger
import java.util.*

class RSA {
    val RANDOM_BIT_LEN = 15

    init {
        val rand = Random()
        val p =BigInteger.probablePrime(RANDOM_BIT_LEN, rand)

        println(rand.toString())
    }
}