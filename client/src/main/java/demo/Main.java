package demo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Runs the seven demo scenarios against the API and prints a result table. */
public final class Main {
    /** One result line of the table. */
    record Row(String scenario, String expected, boolean match, String actual) {}

    /** Not instantiable; only main() is used. */
    private Main() {}

    /** Enrolls identities, runs the scenarios, prints the table; exit code 0 only if all match. */
    public static void main(String[] args) {
        String ca = System.getenv().getOrDefault("CA_URL", "http://ca.demo:8080");
        String url = System.getenv().getOrDefault("API_URL", "https://api.demo:8443");
        String authUrl = System.getenv().getOrDefault("AUTH_URL", "https://auth.demo:8443");
        String grpcTarget = System.getenv().getOrDefault("GRPC_TARGET", "api.demo:9443");
        List<Row> rows = new ArrayList<>();
        try {
            Map<String, String> secrets = secrets(System.getenv("ENROLL_SECRETS"));
            Identity w = Enroller.enroll(ca, "java-writer", "client", "demo", secrets.get("java-writer"));
            Identity r = Enroller.enroll(ca, "java-reader", "client", "demo", secrets.get("java-reader"));
            Identity x = Enroller.enroll(ca, "java-rogue", "client", "rogue", secrets.get("java-rogue"));
            Api writer = new Api(Tls.contextFor(w), url, authUrl);
            Api reader = new Api(Tls.contextFor(r), url, authUrl);
            Api rogue = new Api(Tls.contextFor(x), url, authUrl);

            // 1: writer may read and write. POST /orders replies 201 (created).
            String wt = Api.accessToken(writer.token());
            rows.add(check("1 writer GET /orders", 200, null, writer.get(wt)));
            rows.add(check("1 writer POST /orders", 201, null, writer.post(wt, "book")));

            // 2: reader has no write scope (403), but can still read.
            String rt = Api.accessToken(reader.token());
            rows.add(check("2 reader POST /orders", 403, "insufficient_scope", reader.post(rt, "book")));
            rows.add(check("2 reader GET /orders", 200, null, reader.get(rt)));

            // 3: a token stolen from the writer is bound to the writer's cert, so the reader's cert fails.
            rows.add(check("3 reader replays writer token", 401, "thumbprint_mismatch", reader.get(wt)));

            // 4: rogue-issued cert must be rejected in the TLS layer.
            rows.add(tlsRejected("4 rogue cert", rogue.token()));
            // Control: a dropped connection alone must not pass scenario 4; the API must still serve the writer.
            rows.add(check("4 control: writer still served", 200, null, writer.get(wt)));

            // 5: an outsider has no enrollment secret, so the CA refuses to issue java-writer. The legitimate
            // writer enrolled with its secret above, which is why scenarios 1 to 3 ran at all.
            rows.add(enrollRefused("5 attacker enrolls, no secret", ca, null));
            rows.add(enrollRefused("5 attacker enrolls, wrong secret", ca, java.util.UUID.randomUUID().toString()));

            // 6: a token signed with a key that is not in the auth server's JWKS must be rejected.
            rows.add(check("6 forged token, key not in JWKS", 401, "bad_signature", writer.get(forge(wt))));

            // 7: token exchange. Narrowing works, and every bad exchange is refused with a 400.
            Api.Result ex = writer.exchange(wt, "api.demo", "orders:read");
            rows.add(check("7 writer exchanges down to orders:read", 200, null, ex));
            String nt = Api.accessToken(ex);
            rows.add(check("7 narrowed token GET /orders", 200, null, writer.get(nt)));
            rows.add(check("7 narrowed token POST /orders", 403, "insufficient_scope", writer.post(nt, "book")));
            rows.add(check("7 reader asks orders:write", 400, "invalid_scope scope_not_allowed", reader.exchange(rt, "api.demo", "orders:write")));
            rows.add(check("7 reader uses writer subject token", 400, "invalid_grant thumbprint_mismatch", reader.exchange(wt, "api.demo", null)));
            rows.add(check("7 unknown audience", 400, "invalid_target audience_not_allowed", writer.exchange(wt, "other.demo", null)));

            // 8: the same checks over gRPC. Tokens come from a TokenSource that fetches over mTLS as the channel's identity.
            try (OrdersGrpc gw = new OrdersGrpc(w, grpcTarget, new TokenSource(writer::token, java.time.Clock.systemUTC()));
                 OrdersGrpc gr = new OrdersGrpc(r, grpcTarget, new TokenSource(reader::token, java.time.Clock.systemUTC()));
                 OrdersGrpc gr0 = new OrdersGrpc(r, grpcTarget, null);
                 OrdersGrpc gx = new OrdersGrpc(x, grpcTarget, null)) {
                rows.add(checkGrpc("8 grpc writer Add", "OK", gw.add("book")));
                rows.add(checkGrpc("8 grpc writer List", "OK", gw.list()));
                rows.add(checkGrpc("8 grpc reader Add", "PERMISSION_DENIED insufficient_scope", gr.add("book")));
                rows.add(checkGrpc("8 grpc reader List", "OK", gr.list()));
                // The writer's token goes in a plain header on a channel that uses the reader's cert.
                rows.add(checkGrpc("8 grpc reader replays writer token", "UNAUTHENTICATED thumbprint_mismatch", gr0.listWithToken(wt)));
                rows.add(grpcRejected("8 grpc rogue cert", gx.list()));
                rows.add(checkGrpc("8 grpc control: writer still served", "OK", gw.list()));
            }

            // 9: DPoP. The client cert is still needed at TLS, but the token is bound to a proof key.
            Dpop dp = new Dpop();
            String tokenUrl = authUrl + "/token", ordersUrl = url + "/orders";
            String dt = Api.accessToken(writer.tokenDpop(dp.proof("POST", tokenUrl, null)));
            rows.add(check("9 dpop GET /orders", 200, null, writer.getDpop(dt, dp.proof("GET", ordersUrl, dt))));
            rows.add(check("9 dpop POST /orders", 201, null, writer.postDpop(dt, dp.proof("POST", ordersUrl, dt), "book")));
            rows.add(check("9 dpop proof from other key", 401, "dpop_jkt_mismatch", writer.getDpop(dt, new Dpop().proof("GET", ordersUrl, dt))));
            rows.add(check("9 dpop wrong htu", 401, "dpop_htu", writer.getDpop(dt, dp.proof("GET", ordersUrl + "/other", dt))));
            rows.add(check("9 dpop wrong htm", 401, "dpop_htm", writer.getDpop(dt, dp.proof("POST", ordersUrl, dt))));
            // The same proof twice: the first use must pass, the second is a replay of its jti.
            String once = dp.proof("GET", ordersUrl, dt);
            Api.Result first = writer.getDpop(dt, once);
            if (first.status() != 200) rows.add(check("9 dpop reused jti (first use)", 200, null, first));
            rows.add(check("9 dpop reused jti", 401, "dpop_replay", writer.getDpop(dt, once)));
            rows.add(check("9 dpop token as Bearer", 401, "dpop_required", writer.get(dt)));
        } catch (Exception e) {
            print(rows);
            System.err.println("FAILED: " + e.getMessage() + (e.getCause() != null ? " (" + e.getCause() + ")" : ""));
            System.exit(1);
        }
        print(rows);
        System.exit(rows.stream().allMatch(Row::match) ? 0 : 1);
    }

    /** Copies the claims of a real token, sets a new exp, and signs with a fresh EC key the server does not know. */
    static String forge(String realToken) throws Exception {
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var dec = java.util.Base64.getUrlDecoder();
        var enc = java.util.Base64.getUrlEncoder().withoutPadding();
        var claims = (com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(dec.decode(realToken.split("\\.")[1]));
        claims.put("exp", System.currentTimeMillis() / 1000 + 300);
        String head = enc.encodeToString("{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"forged\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String input = head + "." + enc.encodeToString(json.writeValueAsBytes(claims));
        var kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var sig = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
        sig.initSign(kpg.generateKeyPair().getPrivate());
        sig.update(input.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return input + "." + enc.encodeToString(sig.sign());
    }

    /** Expects the CA to answer 403 to an enrollment as java-writer with the given secret. */
    static Row enrollRefused(String name, String ca, String secret) throws Exception {
        try {
            Enroller.enroll(ca, "java-writer", "client", "demo", secret);
            return new Row(name, "403 enroll refused", false, "cert issued");
        } catch (Enroller.EnrollException e) {
            return new Row(name, "403 enroll refused", e.status() == 403, e.status() + "");
        }
    }

    /** Parses "name=secret,name=secret"; unset or malformed entries are skipped. */
    static Map<String, String> secrets(String env) {
        Map<String, String> m = new HashMap<>();
        if (env != null) for (String kv : env.split(",")) {
            int i = kv.indexOf('=');
            if (i > 0) m.put(kv.substring(0, i), kv.substring(i + 1));
        }
        return m;
    }

    /** Compares status and error reason exactly. */
    static Row check(String name, int status, String reason, Api.Result res) {
        String exp = status + (reason == null ? "" : " " + reason);
        String act = res.error() != null ? describe(res.error())
                : res.status() + (res.reason() == null ? "" : " " + res.reason());
        return new Row(name, exp, res.error() == null && res.status() == status
                && java.util.Objects.equals(reason, res.reason()), act);
    }

    /**
     * Matches an SSLException in the chain, or a plain IOException "Connection reset" or
     * "EOF reached while reading". With TLS 1.3 the client finishes its handshake first,
     * so the server's reject can surface as a reset. Refused/timeout/unknown host do not match.
     */
    static Row tlsRejected(String name, Api.Result res) {
        boolean ok = false;
        for (Throwable t = res.error(); t != null; t = t.getCause()) {
            if (t instanceof javax.net.ssl.SSLException) ok = true;
            if (t.getClass() == java.io.IOException.class && String.valueOf(t.getMessage()).matches(".*(Connection reset|EOF reached while reading).*")) ok = true;
        }
        String act = res.error() != null ? describe(res.error()) : "HTTP " + res.status() + " (not rejected)";
        return new Row(name, "TLS handshake rejected", ok, act);
    }

    /** Compares the gRPC status text ("OK" or "CODE message") exactly. */
    static Row checkGrpc(String name, String expected, OrdersGrpc.Result res) {
        return new Row(name, expected, expected.equals(res.text()), res.text());
    }

    /** A rejected TLS handshake surfaces in gRPC as UNAVAILABLE; any other status (even a clean OK) fails the row. */
    static Row grpcRejected(String name, OrdersGrpc.Result res) {
        return new Row(name, "TLS handshake rejected", res.code() == io.grpc.Status.Code.UNAVAILABLE, res.text());
    }

    /** Exception class and message. */
    private static String describe(Throwable t) {
        return t.getClass().getName() + ": " + t.getMessage();
    }

    /** Prints the SCENARIO / EXPECTED / MATCH / ACTUAL table. */
    private static void print(List<Row> rows) {
        String f = "%-40s %-44s %-6s %s%n";
        System.out.printf(f, "SCENARIO", "EXPECTED", "MATCH", "ACTUAL");
        for (Row r : rows) System.out.printf(f, r.scenario(), r.expected(), r.match() ? "yes" : "NO", r.actual());
    }
}
