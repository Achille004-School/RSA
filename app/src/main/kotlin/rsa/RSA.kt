package rsa

import java.math.BigInteger
import java.util.Random

class RSA(private val bitLength: BitLengths) {
    enum class BitLengths(val bits: Int) {
        WEAK(1024),
        NORMAL(2048),
        STRONG(4096),
    }

    private val rand = Random()

    private var p: BigInteger
    private var q: BigInteger
    var n: BigInteger
        private set
    private var phi: BigInteger
    var e: BigInteger
        private set
    private var d: BigInteger

    init {
        // Choose two distinct prime numbers
        p = generatePrime()
        do {
            q = generatePrime()
        } while (q == p)

        // Compute n = pq
        n = p * q

        // Compute the Carmichael's totient function of the product as λ(n) = lcm(p −
        // 1, q − 1)
        phi = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE))

        // public key
        // Choose any number 1 < e < phi that is coprime to phi.
        do {
            e = generatePrime()
        } while (!(e < phi && e.gcd(phi).equals(BigInteger.ONE)))
        
        // private key
        // Compute d, the modular multiplicative inverse of e mod phi
        d = e.modInverse(phi)
    }

    fun privateKeyParse(num: BigInteger): BigInteger {
        return num.modPow(d, n)
    }

    // numbers go from 64 digits to 128
    private fun generatePrime(): BigInteger {
        return BigInteger.probablePrime(bitLength.bits / 2, rand)
    }

    // function to calculate l.c.m
    private fun lcm(a: BigInteger, b: BigInteger): BigInteger {
        return if (a.signum() != 0 && b.signum() != 0) a.divide(a.gcd(b)).multiply(b).abs()
        else BigInteger.ZERO
    }
}
