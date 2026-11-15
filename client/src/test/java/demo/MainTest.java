package demo;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.ConnectException;
import java.util.Map;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;

class MainTest {
    @Test
    void secretsParsesPairsAndSkipsMalformedEntries() {
        assertEquals(Map.of("a", "1", "b", "x=y"), Main.secrets("a=1,b=x=y,novalue,=nokey"));
        assertTrue(Main.secrets(null).isEmpty());
        assertTrue(Main.secrets("").isEmpty());
    }

    @Test
    void enrollRefusedPassesOnlyOn403() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            assertTrue(Main.enrollRefused("x", ca.url(), null).match());
            assertTrue(Main.enrollRefused("x", ca.url(), ca.wrongSecret).match());
            Main.Row issued = Main.enrollRefused("x", ca.url(), ca.secret);
            assertFalse(issued.match(), "a cert being issued must fail scenario 5");
            assertEquals("cert issued", issued.actual());
        }
    }

    @Test
    void tlsRejectedAcceptsHandshakeFailuresAndResets() {
        assertTrue(Main.tlsRejected("x", new Api.Result(-1, "", new SSLHandshakeException("bad"))).match());
        assertTrue(Main.tlsRejected("x", new Api.Result(-1, "", new IOException("Connection reset"))).match());
        assertTrue(Main.tlsRejected("x", new Api.Result(-1, "", new IOException("EOF reached while reading"))).match());
    }

    @Test
    void tlsRejectedDoesNotPassOnOtherFailuresOrOnSuccess() {
        assertFalse(Main.tlsRejected("x", new Api.Result(-1, "", new ConnectException("Connection refused"))).match());
        assertFalse(Main.tlsRejected("x", new Api.Result(-1, "", new IOException("timed out"))).match());
        assertFalse(Main.tlsRejected("x", new Api.Result(200, "{}", null)).match());
    }

    @Test
    void checkComparesStatusAndReasonExactly() {
        var r = new Api.Result(403, "{\"error\":\"insufficient_scope\"}", null);
        assertTrue(Main.check("x", 403, "insufficient_scope", r).match());
        assertFalse(Main.check("x", 403, "other", r).match());
        assertFalse(Main.check("x", 401, "insufficient_scope", r).match());
        assertFalse(Main.check("x", 403, null, r).match());
    }

    @Test
    void reasonJoinsErrorAndDescription() {
        assertEquals("invalid_grant thumbprint_mismatch",
                new Api.Result(400, "{\"error\":\"invalid_grant\",\"error_description\":\"thumbprint_mismatch\"}", null).reason());
        assertEquals("insufficient_scope", new Api.Result(403, "{\"error\":\"insufficient_scope\"}", null).reason());
        assertNull(new Api.Result(200, "{\"scope\":\"x\"}", null).reason());
    }

    @Test
    void forgeKeepsClaimsSetsNewExpAndSignsWithKidAndRawEcSignature() throws Exception {
        var b = java.util.Base64.getUrlEncoder().withoutPadding();
        String real = "h." + b.encodeToString("{\"sub\":\"java-writer\",\"exp\":1}".getBytes()) + ".s";
        String[] p = Main.forge(real).split("\\.");
        var d = java.util.Base64.getUrlDecoder();
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        assertEquals("ES256", json.readTree(d.decode(p[0])).get("alg").asText());
        assertFalse(json.readTree(d.decode(p[0])).get("kid").asText().isEmpty());
        assertEquals("java-writer", json.readTree(d.decode(p[1])).get("sub").asText());
        assertTrue(json.readTree(d.decode(p[1])).get("exp").asLong() > 1);
        assertEquals(64, d.decode(p[2]).length);
    }

    @Test
    void checkGrpcComparesStatusTextExactly() {
        var denied = new OrdersGrpc.Result(io.grpc.Status.Code.PERMISSION_DENIED, "insufficient_scope");
        assertTrue(Main.checkGrpc("x", "PERMISSION_DENIED insufficient_scope", denied).match());
        assertFalse(Main.checkGrpc("x", "OK", denied).match());
        assertEquals("OK", Main.checkGrpc("x", "OK", new OrdersGrpc.Result(io.grpc.Status.Code.OK, "")).actual());
    }

    @Test
    void grpcRejectedPassesOnlyOnUnavailable() {
        assertTrue(Main.grpcRejected("x", new OrdersGrpc.Result(io.grpc.Status.Code.UNAVAILABLE, "ssl")).match());
        assertFalse(Main.grpcRejected("x", new OrdersGrpc.Result(io.grpc.Status.Code.UNAUTHENTICATED, "x")).match());
        assertFalse(Main.grpcRejected("x", new OrdersGrpc.Result(io.grpc.Status.Code.OK, "")).match());
    }
}
