package demo;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Builds mTLS contexts from an {@link Identity}, entirely in memory (no files on disk). */
public final class Tls {
    private static final char[] PW = new char[0];

    private Tls() {}

    /**
     * Returns a TLS 1.3 context that presents the identity's cert and trusts only its CA.
     * Note: the server sends no CA list, so the JDK presents even a rogue-issued cert
     * and the server rejects it after the handshake message arrives.
     */
    public static SSLContext contextFor(Identity id) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(pem(id.certPem()));
        Certificate ca = cf.generateCertificate(pem(id.caPem()));

        String b64 = id.keyPem().replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        PrivateKey key = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", key, PW, new Certificate[] {cert});

        // Trust only the CA from enrollment: no system roots, so nothing else can vouch for the server.
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", ca);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, PW);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        // TLS 1.3 only: a fixed modern protocol, no downgrade.
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /** Wraps a PEM string as a stream for CertificateFactory. */
    private static ByteArrayInputStream pem(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.US_ASCII));
    }
}
