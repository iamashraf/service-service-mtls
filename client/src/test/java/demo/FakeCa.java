package demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * A stand-in for the Go CA, in the test JVM. It mirrors the real contract: it requires the secret
 * header, verifies the CSR signature, and issues a client cert for the CSR's public key.
 * It records every request so tests can inspect what the client sent.
 */
final class FakeCa implements AutoCloseable {
    /** One recorded /enroll request. */
    record Seen(String secretHeader, JsonNode body) {}

    private static final ObjectMapper JSON = new ObjectMapper();
    final List<Seen> seen = new CopyOnWriteArrayList<>();
    private final HttpServer server;
    private final KeyPair caKey;
    private final X500Principal caName = new X500Principal("CN=fake-ca");
    final String caPem;

    /** The only secret this CA accepts. Random per instance, so no secret is written in the tests. */
    final String secret = UUID.randomUUID().toString();
    /** A secret this CA refuses. */
    final String wrongSecret = UUID.randomUUID().toString();

    /** Starts on a free port. Only {@link #secret} is accepted; anything else gets 403. */
    FakeCa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        caKey = g.generateKeyPair();
        var now = System.currentTimeMillis();
        X509CertificateHolder ca = new JcaX509v3CertificateBuilder(caName, BigInteger.ONE, new Date(now - 60_000),
                new Date(now + 3_600_000), caName, caKey.getPublic())
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate()));
        caPem = pem(ca);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/enroll", ex -> {
            byte[] raw = ex.getRequestBody().readAllBytes();
            String got = ex.getRequestHeaders().getFirst("X-Enroll-Secret");
            JsonNode body = JSON.readTree(raw);
            seen.add(new Seen(got, body));
            int status = 200;
            String out;
            try {
                if (!secret.equals(got)) {
                    status = 403;
                    out = "{\"error\":\"enroll refused\"}";
                } else {
                    out = JSON.writeValueAsString(Map.of("cert_pem", issue(body), "ca_pem", caPem));
                }
            } catch (Exception e) {
                status = 400;
                out = "{\"error\":\"invalid csr\"}";
            }
            byte[] bytes = out.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(status, bytes.length);
            ex.getResponseBody().write(bytes);
            ex.close();
        });
        server.start();
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Issues a client cert for the CSR's key; the name comes from the request, not from the CSR. */
    private String issue(JsonNode body) throws Exception {
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) new PEMParser(new StringReader(body.get("csr_pem").asText())).readObject();
        JcaPKCS10CertificationRequest jcsr = new JcaPKCS10CertificationRequest(csr);
        if (!csr.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(jcsr.getPublicKey()))) {
            throw new IllegalArgumentException("bad csr signature");
        }
        var now = System.currentTimeMillis();
        X509CertificateHolder leaf = new JcaX509v3CertificateBuilder(caName, BigInteger.TWO, new Date(now - 60_000),
                new Date(now + 3_600_000), new X500Principal("CN=" + body.get("name").asText()), jcsr.getPublicKey())
                .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth))
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate()));
        return pem(leaf);
    }

    private static String pem(X509CertificateHolder h) throws Exception {
        StringWriter w = new StringWriter();
        try (JcaPEMWriter p = new JcaPEMWriter(w)) {
            p.writeObject(new JcaX509CertificateConverter().getCertificate(h));
        }
        return w.toString();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
