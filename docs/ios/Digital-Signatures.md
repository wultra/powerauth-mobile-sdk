# Digital Signatures

<!-- SIDEBAR _Sidebar.md -->

Digital signatures are another form of data authentication supported in the PowerAuth protocol. The PowerAuth Mobile SDK provides a unified interface for digital signatures, allowing you to compute or verify digital signatures or MAC tokens.

## Signature Key Identifiers

To compute or verify a signature, you must specify the key used for the operation. The following basic key categories are available:

- **"master"** public keys are used to verify data signed by the server. These keys can be used with or without an activation present in the `PowerAuthSDK` instance.
- **"server"** public keys are personalized keys uniquely associated with an activation. You can use these keys to verify data signed by the server.
- **"device"** private and public keys are stored locally on the device and associated with an activation. You can use these keys to sign data and to verify previously signed data.
- **"MAC"** keys are symmetric keys used to verify MACs calculated by the server.

The table below lists all available key identifiers defined in the `PowerAuthSignatureKeyId` enumeration and operations supported with the identifier:

| Key identifier    | Key Type  | Signature       | Activation  | Sign | Verify | Description |
|-------------------|-----------|-----------------|-------------|------|--------|--------------|
| `master`          | Any       | Any or Hybrid   | No          | No   | Yes    | Use all available "master" public keys for signature verification. |
| `master_EC`       | EC        | ECDSA           | No          | No   | Yes    | Use only the EC-based "master" public key for ECDSA signature verification. |
| `master_ML_DSA`   | ML-DSA    | ML-DSA          | No          | No   | Yes    | Use only the ML-DSA-based "master" public key for ML-DSA signature verification. |
| `server`          | Any       | Any or Hybrid   | Yes         | No   | Yes    | Use all available "server" public keys for signature verification. |
| `server_EC`       | EC        | ECDSA           | Yes         | No   | Yes    | Use only the EC-based "server" public key for ECDSA signature verification. |
| `server_ML_DSA`   | ML-DSA    | ML-DSA          | Yes         | No   | Yes    | Use only the ML-DSA-based "server" public key for ML-DSA signature verification. |
| `device`          | Any       | Any or Hybrid   | Yes         | Yes  | Yes    | Use all available "device" private and public keys for signature computation or verification. |
| `device_EC`       | EC        | ECDSA           | Yes         | Yes  | Yes    | Use only the EC-based "device" private and public key for ECDSA signature computation or verification. |
| `device_ML_DSA`   | ML-DSA    | ML-DSA          | Yes         | Yes  | Yes    | Use only the ML-DSA-based "device" private and public key for ML-DSA signature computation or verification. |
| `macPersonalized` | MAC       | KMAC            | Yes         | No   | Yes    | Use the KMAC-based symmetric key for MAC verification. |

<!-- begin box info -->
If you're interested in more technical details, such as the exact algorithms used for digital signatures, see the [Digital-Signatures.md](Digital-Signatures.md) document.
<!-- end -->

### Signature Key Availability

The availability of key types depends on the selected [PowerAuth Algorithm](Configuration.md#algorithms-for-communication):

- **"EC"** keys are always available.
- **"ML_DSA"** keys are available only if the `EC_P384_ML_L3` or `EC_P384_ML_L5` algorithms are used.
- **"MAC"** keys are available for all algorithms except `LEGACY_P256`.

<!-- begin box warning -->
If you select a key without specifying its exact type (for example, `.master`), it may lead to multiple key selections. For example, the `EC_P384_ML_L3` and `EC_P384_ML_L5` algorithms use two keys for each key category. The format of hybrid signatures is not yet standardized; therefore, the PowerAuth Mobile SDK supports such key identifiers only in JWS functions. JWS, by design, supports multiple keys in signatures.
<!-- end -->

## Sign Data With Device Private Key

To compute a digital signature using an asymmetric device private key, request user credentials (such as password or PIN), specify the signing key (always use the "device" key), and use the following code:

```swift
// 2FA authentication — uses the device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
// Specify the key to sign with. In this case, device_ML_DSA is used,
// and therefore an ML-DSA signature will be produced.
let signingKey = PowerAuthSignatureKeyId.device_ML_DSA
// Unlock the device private key after successful authentication and perform data signing.
powerAuthSDK.calculateDigitalSignature(authentication: auth, forData: data, withKey: signingKey) { signature, error in
    if let signature {
        // Send data and signature to the server
    } else {
        // Authentication or network error
    }
}
```

<!-- begin box info -->
If the `PowerAuthSDK` instance is not configured for the legacy mode (that is, the algorithm is not `LEGACY_P256`), you can also use biometric authentication to access the device private key.
<!-- end -->


## Create JSON Web Signature with Device Private Key

The asymmetric private key signatures described in the previous chapter can be used to create a [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515). The example below demonstrates how to construct a JWS from generic data:

```swift
// 2FA authentication — uses the device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
// Unlock the device private key after successful authentication and perform data signing.
// - The dataType parameter is added to the JWS Protected Header under the "typ" key.
//   A nil parameter means that no "typ" value is included in the header.
// - The compact parameter determines whether the output is a JWS (compact = false) or JWT (compact = true).
powerAuthSDK.calculateJwsSignature(authentication: auth, forData: data, dataType: nil, compact: false, withKey: .device_ML_DSA) { jws, error in
    if let jws {
        // jws contains a JSON string with the JWS object
    } else {
        // Authentication or network error
    }
}
```

The following example demonstrates how to construct a signed JWT:

```swift
// Construct claims dictionary
let claims = [
    "sub": "user-id",
    "first_name": "John",
    "last_name": "Appleseed"
]
guard let claimsData = try? JSONSerialization.data(withJSONObject: claims) else {
    fatalError() // JSON serialization error
}
// 2FA authentication — uses the device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
// Unlock the secure vault, fetch the private key, and perform data signing
powerAuthSDK.calculateJwsSignature(authentication: auth, forData: claimsData, dataType: "JWT", compact: true, withKey: .device_ML_DSA) { jws, error in
    if let jws {
        // jws contains the JWT string
    } else {
        // Authentication or network error
    }
}
```

## Verify Server-Signed Data

This task is useful when you receive arbitrary data from the server and need to verify that it was indeed issued by the server. The `PowerAuthSDK` provides a high-level method for validating data and its associated signature:

```swift
do {
    try powerAuthSDK.verifyDigitalSignature(signature: signature, forData: signedData, withKey: .server_ML_DSA)
    print("Signature is valid")
} catch let error as NSError where error.domain == PowerAuthErrorDomain {
    if error.powerAuthErrorCode == .wrongSignature {
        print("Signature is invalid")
    } else {
        // other cause of failure
    }
}
```

### Verify Data Encoded in QR Code

In cases where you need to verify the authenticity of a QR code created on the server and authenticated with a personalized MAC key (for example, when authenticity is bound to an activation), use the `.macPersonalized` key identifier. For example:

```swift
do {
    try powerAuthSDK.verifyDigitalSignature(signature: signature, forData: signedData, withKey: .macPersonalized)
    print("MAC is valid")
} catch let error as NSError where error.domain == PowerAuthErrorDomain {
    if error.powerAuthErrorCode == .wrongSignature {
        print("MAC is invalid")
    } else {
        // other cause of failure
    }
}
```


## Verify JSON Web Signature

To verify a JSON Web Signature (JWS) created on the server, use the following code:

```swift
do {
    try sdk.verifyJwsSignature(signature: jws, compact: false, strict: true, withKey: .server)
} catch let error as NSError where error.domain == PowerAuthErrorDomain {
    if error.powerAuthErrorCode == .wrongSignature {
        // signature is not valid
    } else {
        // other cause of failure
    }
}
```

Explanation of `verifyJwsSignature` function parameters:

- `signature` - A string containing JWS or JWT signed data.
- `compact` - If `true`, the input string is a compact JWT; otherwise, a full JWS object is expected.
- `strict` — If `true`, all selected keys must successfully verify their corresponding signatures. If `false`, verification succeeds when at least one provided key matches a valid signature; however, invalid or mismatched signatures still result in an error. It is generally recommended to use `true`, unless you have a specific reason to reduce the strict verification.
- `key`- The identifier of the key used for verification. Be aware, that this API doesn't support `.macPersonalized` key.

<!-- begin box warning -->
The compact (JWT) format encodes only a single signature, so it is recommended to specify the exact key type (EC, ML-DSA, etc.) for verification. If a generic key identifier is provided (such as `.server`), the function may fail when the current algorithm results in multiple key selections. You can relax this behavior by setting the `strict` parameter to `false`, but this is generally not recommended. In non-strict mode, an attacker could potentially remove or replace a stronger PQC signature with a weaker one without detection.
<!-- end box -->

## Creating Certificate Signing Request

The PowerAuth SDK can create a Certificate Signing Request (CSR) that can be used to request an X.509 certificate from a Public Key Infrastructure (PKI). The CSR contains a device public key generated by the SDK and is signed with the activation-bound private key.

The created CSR is returned in PEM format, including the `-----BEGIN CERTIFICATE REQUEST-----` and `-----END CERTIFICATE REQUEST-----` lines and newline characters (`\n`).

To create a CSR, use the following code:

```swift
let authentication = PowerAuthAuthentication.possessionWithPassword(password: "1234")
let keyIdentifier = PowerAuthSignatureKeyId.device_ML_DSA

powerAuthSDK.createCertificateSigningRequest(
    authentication: authentication, // authentication object
    distinguishedNames: [ // subject's distinguished names (DN)
        "CN" : "wultra.com",
        "O"  : "Wultra",
        "C"  : "CZ"
    ],
    subjectAltNames: [ // subject's alternative names (SAN)
        "IP: 192.168.1.10",
        "email: admin@example.com"
    ],
    keyIdentifier: keyIdentifier // Key Identifier
) { csr, error in
    if let csr {
        print("CSR: \(csr)")
        // Use the CSR
    } else {
        // Handle error
    }
}
```

<!-- begin box info -->
If the `PowerAuthSDK` instance is not configured for the legacy mode (that is, the algorithm is not `LEGACY_P256`), you can also use biometric authentication to create CSR.
<!-- end -->

## Getting Device Public Keys

Use the following code to retrieve device public keys associated with the activation:

```swift
let allKeys = try powerAuthSDK.exportDevicePublicKeys(format: .der)
if let publicKey = allKeys.first(where: { $0.keyType == .EC }) {
    print("EC key algorithm: \(publicKey.keyAlgorithm)")
    print("  X.509 key data: \(publicKey.keyData.base64EncodedString())")
}
if let publicKey = allKeys.first(where: { $0.keyType == .ML_DSA }) {
    print("ML-DSA key algorithm: \(publicKey.keyAlgorithm)")
    print("      X.509 key data: \(publicKey.keyData.base64EncodedString())")
}
```

Available format specifiers:

- `.der` - The public key is exported in binary X.509 (DER) format.
- `.raw` - The raw key format depends on the key type:
  - **EC keys**: The output is ASN.1 encoded, as defined in **ANSI X9.63**.
  - **ML-DSA keys**: The output contains the raw public key obtained via OpenSSL’s `EVP_PKEY_get_raw_public_key()`.

## Read Next

- [Password Change](Password-Change.md)
