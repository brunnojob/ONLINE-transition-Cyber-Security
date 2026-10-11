import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

object GuardSigner {
    fun sign(key: ByteArray, payload: ByteArray, expectedOrigin: String): String {
        val fields = payload.toString(Charsets.US_ASCII).split('\n')
        require(fields.size == 10 && fields[0] == "GUARD-V1" && fields[9] == expectedOrigin)
        require(fields[8].toLong() > System.currentTimeMillis() / 1000)
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(key))
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(payload)
            Base64.getEncoder().encodeToString(sign())
        }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 3)
        println(sign(Files.readAllBytes(Path.of(args[0])), Files.readAllBytes(Path.of(args[1])), args[2]))
    }
}
