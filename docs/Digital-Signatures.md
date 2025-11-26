# Digital Signatures

This document contains technical details about algorithms for digital signatures for each PowerAuth Algorithm.

| PowerAuth Algorithm | Key type  |           | DSA                | JWS ID    |
|---------------------|-----------|-----------|--------------------|-----------|
| EC_P384_ML_L3       | EC        | P-384     | ECDSA with SHA-384 | ES384     |
|                     | ML-DSA    | ML-DSA-65 | ML-DSA-65          | ML-DSA-65 |
| EC_P384_ML_L5       | EC        | P-384     | ECDSA with SHA-384 | ES384     |
|                     | ML-DSA    | ML-DSA-87 | ML-DSA-87          | ML-DSA-87 |
| EC_P384             | EC        | P-384     | ECDSA with SHA-384 | ES384     |
| LEGACY_P256         | EC        | P-256     | ECDSA with SHA-256 | ES256     |

> Be aware, that hybrid signatures are supported only in JWS specific API. The error is reported if you try to compute or validate hybrid signature in non-JWS API.