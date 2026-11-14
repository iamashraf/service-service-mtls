package demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.StringWriter;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Gets an identity from the mock CA over plain HTTP.
 * The key pair is made here and only a CSR is sent, so the private key never leaves the client.
 * Demo shortcut: the CA cert is trusted from this same unauthenticated call. A real client would
 * pin the CA out of band. The CA decides name and SANs, so the CSR subject is only a label.
 */
public final class Enroller {
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Non-200 reply from /enroll; status 403 means the enrollment secret was refused. */
    public static final class EnrollException extends IllegalStateException {
        private final int status;

        EnrollException(String name, int status, String body) {
            super("enroll " + name + " failed: " + status + " " + body);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    private Enroller() {}

    /**
     * POSTs /enroll with a CSR and the enrollment secret (null sends none) and returns the identity.
     * Retries up to 20 x 250ms on connection errors only (the CA may still be starting);
     * any non-200 reply throws {@link EnrollException}.
     */
    public static Identity enroll(String caUrl, String name, String kind, String issuer, String secret) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + name), kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate()));
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(pem)) {
            w.writeObject(csr);
        }
        String body = JSON.writeValueAsString(Map.of(
                "name", name, "kind", kind, "dns", new String[0], "issuer", issuer, "csr_pem", pem.toString()));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(caUrl + "/enroll"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json");
        if (secret != null) b.header("X-Enroll-Secret", secret);
        HttpRequest req = b.POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        for (int attempt = 1; ; attempt++) {
            try {
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() != 200) {
                    throw new EnrollException(name, r.statusCode(), r.body());
                }
                JsonNode n = JSON.readTree(r.body());
                String keyPem = "-----BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(kp.getPrivate().getEncoded())
                        + "\n-----END PRIVATE KEY-----\n";
                return new Identity(n.get("cert_pem").asText(), keyPem, n.get("ca_pem").asText());
            } catch (ConnectException e) {
                if (attempt >= 20) {
                    throw new IllegalStateException("CA not reachable at " + caUrl + " after 20 tries", e);
                }
                Thread.sleep(250);
            }
        }
    }
}
