package demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** Calls the API over mTLS as one identity. */
public final class Api {
    /** Outcome of one call: HTTP status and body, or the exception if the call threw. */
    public record Result(int status, String body, Exception error) {
        /** Returns the JSON "error", plus " " and "error_description" when present; null if there is no error. */
        public String reason() {
            try {
                JsonNode n = new ObjectMapper().readTree(body);
                JsonNode e = n.get("error");
                if (e == null) return null;
                JsonNode d = n.get("error_description");
                return d == null ? e.asText() : e.asText() + " " + d.asText();
            } catch (Exception ex) {
                return null;
            }
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    // Only the very first call of the run retries refused connections (the API may still be starting).
    private static final AtomicBoolean FIRST = new AtomicBoolean(true);

    private final HttpClient http;
    private final String base;
    private final String authBase;

    /** Creates a client using the context's identity: /orders goes to {@code base}, /token to {@code authBase}. */
    public Api(SSLContext ctx, String base, String authBase) {
        SSLParameters p = new SSLParameters();
        p.setProtocols(new String[] {"TLSv1.3"}); // TLS 1.3 only
        // Hostname check stays on: HTTPS algorithm is the default and we never override it.
        this.http = HttpClient.newBuilder().sslContext(ctx).sslParameters(p)
                .connectTimeout(Duration.ofSeconds(5)).build();
        this.base = base;
        this.authBase = authBase;
    }

    /** POST /token with no body; returns the raw result. */
    public Result token() {
        return send(authBase, "POST", "/token", null, null, null, null);
    }

    /** POST /token as a token exchange (form-encoded); scope may be null to keep the subject's scope. */
    public Result exchange(String subjectToken, String audience, String scope) {
        String form = "grant_type=" + enc("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&subject_token=" + enc(subjectToken)
                + "&subject_token_type=" + enc("urn:ietf:params:oauth:token-type:access_token")
                + "&audience=" + enc(audience) + (scope == null ? "" : "&scope=" + enc(scope));
        return send(authBase, "POST", "/token", null, null, form, "application/x-www-form-urlencoded");
    }

    /** POST /token with a DPoP proof header; the token comes back bound to the proof's key. */
    public Result tokenDpop(String proof) {
        return send(authBase, "POST", "/token", null, proof, null, null);
    }

    private static String enc(String v) {
        return java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8);
    }

    /** Extracts access_token from a successful /token result; throws if missing. */
    public static String accessToken(Result r) throws Exception {
        if (r.error() != null) throw r.error();
        if (r.status() != 200) throw new IllegalStateException("token failed: " + r.status() + " " + r.body());
        String token = JSON.readTree(r.body()).path("access_token").asText("");
        if (token.isEmpty()) throw new IllegalStateException("token response has no access_token: " + r.body());
        return token;
    }

    /** GET /orders with a Bearer token. */
    public Result get(String token) {
        return send(base, "GET", "/orders", "Bearer " + token, null, null, "application/json");
    }

    /** GET /orders with {@code Authorization: DPoP <token>} and a proof. */
    public Result getDpop(String token, String proof) {
        return send(base, "GET", "/orders", "DPoP " + token, proof, null, "application/json");
    }

    /** POST /orders {"item": item} with {@code Authorization: DPoP <token>} and a proof. */
    public Result postDpop(String token, String proof, String item) {
        try {
            return send(base, "POST", "/orders", "DPoP " + token, proof, JSON.writeValueAsString(Map.of("item", item)), "application/json");
        } catch (Exception e) {
            return new Result(-1, "", e);
        }
    }

    /** POST /orders {"item": item} with a Bearer token. */
    public Result post(String token, String item) {
        try {
            return send(base, "POST", "/orders", "Bearer " + token, null, JSON.writeValueAsString(Map.of("item", item)), "application/json");
        } catch (Exception e) {
            return new Result(-1, "", e);
        }
    }

    /** Sends one request; never throws. Retries ConnectException up to 20 x 250ms on the run's first call only. */
    private Result send(String host, String method, String path, String auth, String dpop, String json, String type) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(host + path)).timeout(Duration.ofSeconds(5));
        if (auth != null) b.header("Authorization", auth);
        if (dpop != null) b.header("DPoP", dpop);
        if (json != null) b.header("Content-Type", type);
        b.method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json));
        HttpRequest req = b.build();
        int tries = FIRST.getAndSet(false) ? 20 : 1;
        for (int i = 1; ; i++) {
            try {
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                return new Result(r.statusCode(), r.body(), null);
            } catch (ConnectException e) {
                if (i >= tries) return new Result(-1, "", e);
                try { Thread.sleep(250); } catch (InterruptedException ie) { return new Result(-1, "", ie); }
            } catch (Exception e) {
                return new Result(-1, "", e);
            }
        }
    }
}
