package rsa

import java.math.BigInteger
import java.time.LocalTime
import java.time.temporal.ChronoUnit
import kotlin.math.absoluteValue

fun publicKeyParse(letter: BigInteger, host2e: BigInteger, host2n: BigInteger): BigInteger {
    // encrypt first with sender private key and then with recipient public key
    return letter.modPow(host2e, host2n)
}

fun main(args: Array<String>) {
    val result = StringBuffer()
    for (element in args) {
        result.append("$element ")
    }
    result.deleteCharAt(result.length - 1)

    val message = result.toString()
    println("Original message: $message\n")

    val host1 = RSA(RSA.BitLengths.STRONG)
    val host2 = RSA(RSA.BitLengths.STRONG)

    val before = LocalTime.now()

    println("Encrypted message:")
    val encryptedMessage = ArrayList<BigInteger>()
    val encryptedHash = host1.privateKeyParse(BigInteger.valueOf(message.hashCode().toLong().absoluteValue))
    for (c in message) {
        val encryptedChar = publicKeyParse(BigInteger.valueOf(c.code.toLong()), host2.e, host2.n)
        println("$encryptedChar")
        encryptedMessage.add(encryptedChar)
    }

    val middle = LocalTime.now()
    println("in " + (before.until(middle, ChronoUnit.NANOS).toDouble() / 1_000_000) + " ms\n")

    var decrypted = ""
    val decryptedHash = encryptedHash.modPow(host1.e, host1.n)
    for(n in encryptedMessage) {
        val decryptedChar = host2.privateKeyParse(n)
        decrypted += decryptedChar.toInt().toChar()
    }

    val after = LocalTime.now()
    println("Decrypted message: $decrypted in " + (middle.until(after, ChronoUnit.NANOS).toDouble() / 1_000_000) + " ms")

    val decryptedMessageHash = BigInteger.valueOf(decrypted.hashCode().toLong().absoluteValue)
    val integrity = decryptedMessageHash.equals(decryptedHash)

    println("Message integrity is " + if (integrity) "verified" else "compromised")
}
