package demo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Runs the five demo scenarios against the API and prints a result table. */
public final class Main {
    /** One result line of the table. */
    record Row(String scenario, String expected, boolean match, String actual) {}

    /** Not instantiable; only main() is used. */
    private Main() {}

    /** Enrolls identities, runs the scenarios, prints the table; exit code 0 only if all match. */
    public static void main(String[] args) {
        String ca = System.getenv().getOrDefault("CA_URL", "http://ca.demo:8080");
        String url = System.getenv().getOrDefault("API_URL", "https://api.demo:8443");
        List<Row> rows = new ArrayList<>();
        try {
            Map<String, String> secrets = secrets(System.getenv("ENROLL_SECRETS"));
            Identity w = Enroller.enroll(ca, "java-writer", "client", "demo", secrets.get("java-writer"));
            Identity r = Enroller.enroll(ca, "java-reader", "client", "demo", secrets.get("java-reader"));
            Identity x = Enroller.enroll(ca, "java-rogue", "client", "rogue", secrets.get("java-rogue"));
            Api writer = new Api(Tls.contextFor(w), url);
            Api reader = new Api(Tls.contextFor(r), url);
            Api rogue = new Api(Tls.contextFor(x), url);

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
        } catch (Exception e) {
            print(rows);
            System.err.println("FAILED: " + e.getMessage() + (e.getCause() != null ? " (" + e.getCause() + ")" : ""));
            System.exit(1);
        }
        print(rows);
        System.exit(rows.stream().allMatch(Row::match) ? 0 : 1);
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

    /** Exception class and message. */
    private static String describe(Throwable t) {
        return t.getClass().getName() + ": " + t.getMessage();
    }

    /** Prints the SCENARIO / EXPECTED / MATCH / ACTUAL table. */
    private static void print(List<Row> rows) {
        String f = "%-32s %-26s %-6s %s%n";
        System.out.printf(f, "SCENARIO", "EXPECTED", "MATCH", "ACTUAL");
        for (Row r : rows) System.out.printf(f, r.scenario(), r.expected(), r.match() ? "yes" : "NO", r.actual());
    }
}
