package rsa

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.math.BigInteger
import java.net.*
import kotlin.math.absoluteValue

class Peer {
    private val SERVER_PORT = 42000

    private val socket: Socket
    private var sender = true

    private val BIT_LENGTH = RSA.BitLengths.NORMAL
    private val rsa: RSA

    private fun connect(): Socket? {
        var socket: Socket? = null

        try {
            socket = Socket(InetAddress.getLocalHost().hostAddress, SERVER_PORT)
        } catch (ex: Exception) {
            when (ex) {
                is SocketTimeoutException, is ConnectException -> {
                    println("Waiting for another user...")
                    socket = ServerSocket(SERVER_PORT).accept()
                    sender = false
                }
                else -> {
                    println("There was an error.")
                    ex.printStackTrace()
                }
            }
        }

        if (socket != null) println("User found")
        return socket
    }

    init {
        socket = connect()!!
        rsa = RSA(BIT_LENGTH)
    }

    fun run() {
        val hostInput = BufferedReader(InputStreamReader(socket.getInputStream()))
        val hostOutput = PrintWriter(socket.getOutputStream())

        println("Key bit length is " + BIT_LENGTH.bits + ".\n")
        hostOutput.println(rsa.e)
        hostOutput.println(rsa.n)
        hostOutput.flush()

        val e2 = BigInteger(hostInput.readLine())
        val n2 = BigInteger(hostInput.readLine())

        while (socket.isConnected) {
            if (sender) {
                print("Write something to send: ")
                val message = readln()

                // Send encrypted message
                for (c in message) {
                    val encryptedChar = publicKeyParse(BigInteger.valueOf(c.code.toLong()), e2, n2)
                    hostOutput.println(encryptedChar)
                }

                val encryptedHash =
                        rsa.privateKeyParse(
                                BigInteger.valueOf(message.hashCode().toLong().absoluteValue)
                        )
                hostOutput.println("HASH$encryptedHash")

                hostOutput.flush()
                println("Sent.")
            } else {
                println("Waiting for message...")

                var decrypted = ""
                val decryptedHash: BigInteger
                while (true) {
                    var encrypted = hostInput.readLine()
                    if (encrypted.contains("HASH")) {
                        encrypted = encrypted.replace("HASH", "")
                        decryptedHash = publicKeyParse(BigInteger(encrypted), e2, n2)
                        break
                    } else {
                        val decryptedChar = rsa.privateKeyParse(BigInteger(encrypted))
                        decrypted += decryptedChar.toInt().toChar()
                    }
                }

                println("Message: $decrypted")

                val decryptedMessageHash =
                        BigInteger.valueOf(decrypted.hashCode().toLong().absoluteValue)
                val integrity = decryptedMessageHash.equals(decryptedHash)

                println("Message integrity is " + if (integrity) "verified" else "compromised")
            }

            println()
            sender = !sender
        }
    }

    private fun publicKeyParse(letter: BigInteger, e2: BigInteger, n2: BigInteger): BigInteger {
        return letter.modPow(e2, n2)
    }
}
