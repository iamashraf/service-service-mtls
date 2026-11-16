package demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.UUID;

/** Builds DPoP proofs (RFC 9449) with an in-memory EC P-256 key. */
public final class Dpop {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final KeyPair key;
    private final String x;
    private final String y;

    /** Creates a fresh key; each instance is one proof-of-possession identity. */
    public Dpop() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        key = kpg.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) key.getPublic();
        x = B64.encodeToString(fixed32(pub.getW().getAffineX()));
        y = B64.encodeToString(fixed32(pub.getW().getAffineY()));
    }

    /** The key's RFC 7638 thumbprint, as the server compares it to cnf.jkt. */
    public String jkt() throws Exception {
        return jkt(x, y);
    }

    /** RFC 7638 thumbprint of an EC key: SHA-256 of the required members in lexicographic order. */
    static String jkt(String x, String y) throws Exception {
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
        return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    /** A proof with a random jti; {@code token} is the access token to bind via ath, or null (token request). */
    public String proof(String htm, String htu, String token) throws Exception {
        return proof(htm, htu, token, UUID.randomUUID().toString());
    }

    /** Same, with a chosen jti (to send the same proof twice, build it once and reuse the string). */
    public String proof(String htm, String htu, String token, String jti) throws Exception {
        ObjectNode jwk = JSON.createObjectNode().put("kty", "EC").put("crv", "P-256").put("x", x).put("y", y);
        ObjectNode head = JSON.createObjectNode().put("typ", "dpop+jwt").put("alg", "ES256");
        head.set("jwk", jwk);
        ObjectNode claims = JSON.createObjectNode().put("jti", jti).put("htm", htm).put("htu", htu)
                .put("iat", System.currentTimeMillis() / 1000);
        if (token != null) {
            claims.put("ath", B64.encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII))));
        }
        String input = B64.encodeToString(JSON.writeValueAsBytes(head)) + "." + B64.encodeToString(JSON.writeValueAsBytes(claims));
        // The P1363 format is JWS's raw R||S (64 bytes for P-256), not DER.
        Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
        sig.initSign(key.getPrivate());
        sig.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + B64.encodeToString(sig.sign());
    }

    /** Big-endian, exactly 32 bytes (BigInteger adds a sign byte or drops leading zeros). */
    private static byte[] fixed32(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) System.arraycopy(b, b.length - 32, out, 0, 32);
        else System.arraycopy(b, 0, out, 32 - b.length, b.length);
        return out;
    }
}
