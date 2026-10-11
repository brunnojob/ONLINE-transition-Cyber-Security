import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class GuardSigner {
    public static String sign(byte[] encodedKey, byte[] payload, String expectedOrigin) throws Exception {
        String[] fields = new String(payload, java.nio.charset.StandardCharsets.US_ASCII).split("\n", -1);
        if (fields.length != 10 || !fields[0].equals("GUARD-V1") || !fields[9].equals(expectedOrigin)) {
            throw new SecurityException("Untrusted authorization envelope");
        }
        if (Long.parseLong(fields[8]) <= System.currentTimeMillis() / 1000) {
            throw new SecurityException("Expired authorization envelope");
        }
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encodedKey)));
        signer.update(payload);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Usage: GuardSigner key.der payload.txt expected-origin");
        System.out.println(sign(Files.readAllBytes(Path.of(args[0])), Files.readAllBytes(Path.of(args[1])), args[2]));
    }
}
