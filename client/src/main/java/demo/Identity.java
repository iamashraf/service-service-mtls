package demo;

/** A client identity from the CA: PEM cert, PKCS8 EC key, and the demo CA cert to trust. */
public record Identity(String certPem, String keyPem, String caPem) {}
