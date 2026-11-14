package demo;

import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

class EnrollerTest {
    private static PrivateKey key(String pem) throws Exception {
        String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }

    private static X509Certificate cert(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void sendsCsrAndSecretNeverThePrivateKey() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            Identity id = Enroller.enroll(ca.url(), "java-writer", "client", "demo", ca.secret);

            var seen = ca.seen.get(0);
            assertEquals(ca.secret, seen.secretHeader());
            assertFalse(seen.body().has("key_pem"));
            assertFalse(seen.body().toString().contains("PRIVATE"));

            // the CSR is signed by the key the client kept: its public key verifies a signature from that key
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest)
                    new PEMParser(new StringReader(seen.body().get("csr_pem").asText())).readObject();
            PublicKey csrPub = new JcaPKCS10CertificationRequest(csr).getPublicKey();
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(key(id.keyPem()));
            s.update(new byte[] {1, 2, 3});
            byte[] sig = s.sign();
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(csrPub);
            v.update(new byte[] {1, 2, 3});
            assertTrue(v.verify(sig), "CSR key is not the client's key");

            // and the returned cert is for that same key
            assertEquals(csrPub, cert(id.certPem()).getPublicKey());
            assertEquals("CN=java-writer", cert(id.certPem()).getSubjectX500Principal().getName());
            assertEquals(ca.caPem, id.caPem());
        }
    }

    @Test
    void eachEnrollmentMakesANewKey() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            Identity a = Enroller.enroll(ca.url(), "java-writer", "client", "demo", ca.secret);
            Identity b = Enroller.enroll(ca.url(), "java-writer", "client", "demo", ca.secret);
            assertNotEquals(a.keyPem(), b.keyPem());
        }
    }

    @Test
    void noSecretMeansNoHeader() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            var e = assertThrows(Enroller.EnrollException.class,
                    () -> Enroller.enroll(ca.url(), "java-writer", "client", "demo", null));
            assertEquals(403, e.status());
            assertNull(ca.seen.get(0).secretHeader());
        }
    }

    @Test
    void wrongSecretIsRefusedWithItsStatus() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            var e = assertThrows(Enroller.EnrollException.class,
                    () -> Enroller.enroll(ca.url(), "java-writer", "client", "demo", ca.wrongSecret));
            assertEquals(403, e.status());
            assertTrue(e.getMessage().contains("403"));
        }
    }

    @Test
    void enrolledIdentityBuildsATls13Context() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            Identity id = Enroller.enroll(ca.url(), "java-writer", "client", "demo", ca.secret);
            assertEquals("TLSv1.3", Tls.contextFor(id).getProtocol());
        }
    }
}
