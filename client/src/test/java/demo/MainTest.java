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
}
