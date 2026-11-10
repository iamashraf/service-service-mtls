# Learnings

## Task 1: certificate thumbprint

`x5t#S256` is the SHA-256 of a certificate's DER bytes, base64url encoded with no padding. It is 43 characters.
We hash the DER bytes because they are the one canonical form. Re-encoding the PEM or reading fields can differ, the raw bytes cannot.
The thumbprint names one exact certificate. It says nothing about who the owner is. A CN is just text inside the cert.
Gotcha: base64url with padding (`=`) or std base64 (`+`, `/`) gives a different string and the match silently fails.
