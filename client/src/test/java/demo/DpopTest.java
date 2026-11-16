package demo;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class DpopTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Decoder D = Base64.getUrlDecoder();

    @Test
    void proofHasDpopHeaderClaimsAndARawSignatureThatVerifiesWithTheJwk() throws Exception {
        Dpop d = new Dpop();
        String p = d.proof("GET", "https://api.demo:8443/orders", "tok");
        String[] parts = p.split("\\.");
        JsonNode head = JSON.readTree(D.decode(parts[0]));
        JsonNode claims = JSON.readTree(D.decode(parts[1]));
        byte[] sig = D.decode(parts[2]);

        assertEquals("dpop+jwt", head.get("typ").asText());
        assertEquals("ES256", head.get("alg").asText());
        assertEquals("EC", head.at("/jwk/kty").asText());
        assertEquals("P-256", head.at("/jwk/crv").asText());
        assertEquals("GET", claims.get("htm").asText());
        assertEquals("https://api.demo:8443/orders", claims.get("htu").asText());
        assertFalse(claims.get("jti").asText().isEmpty());
        assertTrue(Math.abs(claims.get("iat").asLong() - System.currentTimeMillis() / 1000) < 5);
        byte[] sha = MessageDigest.getInstance("SHA-256").digest("tok".getBytes(StandardCharsets.US_ASCII));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(sha), claims.get("ath").asText());

        assertEquals(64, sig.length, "JWS ES256 signature is raw R||S, not DER");
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECPoint w = new ECPoint(new BigInteger(1, D.decode(head.at("/jwk/x").asText())),
                new BigInteger(1, D.decode(head.at("/jwk/y").asText())));
        PublicKey pub = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, ap.getParameterSpec(ECParameterSpec.class)));
        Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
        v.initVerify(pub);
        v.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(v.verify(sig));
    }

    @Test
    void tokenRequestProofHasNoAthAndEachProofHasANewJti() throws Exception {
        Dpop d = new Dpop();
        JsonNode a = JSON.readTree(D.decode(d.proof("POST", "https://auth.demo:8443/token", null).split("\\.")[1]));
        JsonNode b = JSON.readTree(D.decode(d.proof("POST", "https://auth.demo:8443/token", null).split("\\.")[1]));
        assertFalse(a.has("ath"));
        assertNotEquals(a.get("jti").asText(), b.get("jti").asText());
    }

    @Test
    void jktMatchesRfc7638ForAKnownKey() throws Exception {
        // Key from RFC 7515 appendix A.3; the expected value was computed independently with Python hashlib
        // over {"crv":"P-256","kty":"EC","x":...,"y":...}.
        assertEquals("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
                Dpop.jkt("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"));
    }

    @Test
    void instanceJktIsTheThumbprintOfItsOwnJwk() throws Exception {
        Dpop d = new Dpop();
        JsonNode jwk = JSON.readTree(D.decode(d.proof("GET", "u", null).split("\\.")[0])).get("jwk");
        assertEquals(Dpop.jkt(jwk.get("x").asText(), jwk.get("y").asText()), d.jkt());
    }
}
