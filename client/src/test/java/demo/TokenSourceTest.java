package demo;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class TokenSourceTest {
    /** A clock the test moves by hand. */
    static final class FakeClock extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId z) { return this; }
        @Override public Instant instant() { return now; }
    }

    @Test
    void cachesUntilThirtySecondsBeforeExpiryThenRefetches() throws Exception {
        FakeClock clock = new FakeClock();
        AtomicInteger n = new AtomicInteger();
        TokenSource ts = new TokenSource(() -> {
            int i = n.incrementAndGet();
            return new Api.Result(200, "{\"access_token\":\"t" + i + "\",\"expires_in\":300}", null);
        }, clock);
        assertEquals("t1", ts.token());
        clock.now = clock.now.plus(Duration.ofSeconds(269));
        assertEquals("t1", ts.token());
        assertEquals(1, n.get());
        clock.now = clock.now.plusSeconds(1); // 270s = 300 - 30
        assertEquals("t2", ts.token());
        assertEquals(2, n.get());
    }

    @Test
    void failedFetchThrowsAndIsNotCached() {
        TokenSource ts = new TokenSource(() -> new Api.Result(401, "{}", null), new FakeClock());
        assertThrows(IllegalStateException.class, ts::token);
    }
}
