# Digital Signatures

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

Digital signatures are another form of data authentication supported in the PowerAuth protocol. The PowerAuth Mobile SDK provides a unified interface for digital signatures, allowing you to compute or verify digital signatures or MAC tokens.

## Signature Key Identifiers

To compute or verify a signature, you must specify the key used for the operation. The following basic key categories are available:

- **"master"** public keys are used to verify data signed by the server. These keys can be used with or without an activation present in the `PowerAuthSDK` instance.
- **"server"** public keys are personalized keys uniquely associated with an activation. You can use these keys to verify data signed by the server.
- **"device"** private and public keys are stored locally on the device and associated with an activation. You can use these keys to sign data and to verify previously signed data.
- **"MAC"** keys are symmetric keys used to verify MACs calculated by the server.

The table below lists all available key identifiers defined in the `PowerAuthSignatureKeyId` enumeration and operations supported with the identifier:

| Key identifier     | Key Type  | Signature       | Activation  | Sign | Verify | Description |
|--------------------|-----------|-----------------|-------------|------|--------|--------------|
| `MASTER`           | Any       | Any or Hybrid   | No          | No   | Yes    | Use all available "master" public keys for signature verification. |
| `MASTER_EC`        | EC        | ECDSA           | No          | No   | Yes    | Use only the EC-based "master" public key for ECDSA signature verification. |
| `MASTER_ML_DSA`    | ML-DSA    | ML-DSA          | No          | No   | Yes    | Use only the ML-DSA-based "master" public key for ML-DSA signature verification. |
| `SERVER`           | Any       | Any or Hybrid   | Yes         | No   | Yes    | Use all available "server" public keys for signature verification. |
| `SERVER_EC`        | EC        | ECDSA           | Yes         | No   | Yes    | Use only the EC-based "server" public key for ECDSA signature verification. |
| `SERVER_ML_DSA`    | ML-DSA    | ML-DSA          | Yes         | No   | Yes    | Use only the ML-DSA-based "server" public key for ML-DSA signature verification. |
| `DEVICE`           | Any       | Any or Hybrid   | Yes         | Yes  | Yes    | Use all available "device" private and public keys for signature computation or verification. |
| `DEVICE_EC`        | EC        | ECDSA           | Yes         | Yes  | Yes    | Use only the EC-based "device" private and public key for ECDSA signature computation or verification. |
| `DEVICE_ML_DSA`    | ML-DSA    | ML-DSA          | Yes         | Yes  | Yes    | Use only the ML-DSA-based "device" private and public key for ML-DSA signature computation or verification. |
| `MAC_PERSONALIZED` | MAC       | KMAC            | Yes         | No   | Yes    | Use the KMAC-based symmetric key for MAC verification. |

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

```kotlin
// 2FA authentication — uses the device-related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")
// Specify the key to sign with. In this case, DEVICE_ML_DSA is used,
// and therefore an ML-DSA signature will be produced.
val signingKey = PowerAuthSignatureKeyId.DEVICE_ML_DSA
// Data to sign
val data = "hello".getBytes()
// Calculate signature
powerAuthSDK.calculateDigitalSignature(context, authentication, data, signingKey, object: IDigitalSignatureListener {
    override fun onDigitalSignatureSucceed(signature: ByteArray) {
        // Use data signature...
    }

    override fun onDigitalSignatureFailed(throwable: Throwable) {
        // Report error
    }
})
```

<!-- begin box info -->
If the `PowerAuthSDK` instance is not configured for the legacy mode (that is, the algorithm is not `LEGACY_P256`), you can also use biometric authentication to access the device private key.
<!-- end -->

## Create JSON Web Signature with Device Private Key

The asymmetric private key signatures described in the previous chapter can be used to create a [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515). The example below demonstrates how to construct a JWS from generic data:

```kotlin
// 2FA authentication — uses the device-related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")
// Specify the key to sign with. In this case, DEVICE_ML_DSA is used,
// and therefore an ML-DSA signature will be produced.
val signingKey = PowerAuthSignatureKeyId.DEVICE_ML_DSA
// Data to sign
val data = "hello".getBytes()
// Unlock the device private key after successful authentication and perform data signing.
// - The dataType parameter is added to the JWS Protected Header under the "typ" key.
//   A null parameter means that no "typ" value is included in the header.
// - The compact parameter determines whether the output is a JWS (compact = false) or JWT (compact = true).
powerAuthSDK.calculateJwsSignature(context, authentication, data, null, false, signingKey, object: IJwsSignatureListener {
    override fun onJwsSignatureSucceed(signedData: String, compactForm: Boolean) {
        // Use signed data
    }

    override fun onJwsSignatureFailed(throwable: Throwable) {
        // Report error
    }    
})
```

The following example demonstrates how to construct a signed JWT:

```kotlin
// Construct claims array
val claims = mapOf(
    "sub" to "user-id", 
    "first_name" to "John",
    "last_name" to "Appleseed"
)
// Convert to JSON bytes
val claimsData = Gson().toJson(claims).toByteArray()
// 2FA authentication — uses the device-related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")
// Specify the key to sign with. In this case, DEVICE_ML_DSA is used,
// and therefore an ML-DSA signature will be produced.
val signingKey = PowerAuthSignatureKeyId.DEVICE_ML_DSA
// Unlock the secure vault, fetch the private key, and perform data signing
powerAuthSDK.calculateJwsSignature(context, authentication, claimsData, "JWT", true, signingKey, object: IJwsSignatureListener {
    override fun onJwsSignatureSucceed(signedData: String, compactForm: Boolean) {
        // Use signed data
    }

    override fun onJwsSignatureFailed(throwable: Throwable) {
        // Report error
    }    
})
```

## Verify Server-Signed Data

This task is useful when you receive arbitrary data from the server and need to verify that it was indeed issued by the server. The `PowerAuthSDK` provides a high-level method for validating data and its associated signature:

```kotlin
try {
    verifyDigitalSignature(signature, signedData, PowerAuthSignatureKeyId.SERVER_ML_DSA)
    // success, signature is valid
} catch (exception: PowerAuthErrorException) {
    // failure
    if (exception.powerAuthErrorCode == PowerAuthErrorCodes.WRONG_SIGNATURE) {
        // Invalid signature
    } else {
        // Other failure, such as missing activation
    }
}
```

### Verify Data Encoded in QR Code

In cases where you need to verify the authenticity of a QR code created on the server and authenticated with a personalized MAC key (for example, when authenticity is bound to an activation), use the `MAC_PERSONALIZED` key identifier. For example:

```kotlin
try {
    verifyDigitalSignature(signature, signedData, PowerAuthSignatureKeyId.MAC_PERSONALIZED)
    // success, MAC is valid
} catch (exception: PowerAuthErrorException) {
    // failure
    if (exception.powerAuthErrorCode == PowerAuthErrorCodes.WRONG_SIGNATURE) {
        // Invalid MAC
    } else {
        // Other failure, such as missing activation
    }
}
```

## Verify JSON Web Signature

To verify a JSON Web Signature (JWS) created on the server, use the following code:

```kotlin
try {
    verifyJwsSignature(jws, false, true, PowerAuthSignatureKeyId.SERVER)
    // success, JWS is valid
} catch (exception: PowerAuthErrorException) {
    // failure
    if (exception.powerAuthErrorCode == PowerAuthErrorCodes.WRONG_SIGNATURE) {
        // Invalid signature
    } else {
        // Other failure, such as missing activation
    }
}
```

Explanation of `verifyJwsSignature` function parameters:

- `signature` - A string containing JWS or JWT signed data.
- `compactForm` - If `true`, the input string is a compact JWT; otherwise, a full JWS object is expected.
- `strictVerify` — If `true`, all selected keys must successfully verify their corresponding signatures. If `false`, verification succeeds when at least one provided key matches a valid signature; however, invalid or mismatched signatures still result in an error. It is generally recommended to use `true`, unless you have a specific reason to reduce the strict verification.
- `keyIdentifier`- The identifier of the key used for verification. Be aware, that this API doesn't support `PowerAuthSignatureKeyId.MAC_PERSONALIZED` key.

<!-- begin box warning -->
The compact (JWT) format encodes only a single signature, so it is recommended to specify the exact key type (EC, ML-DSA, etc.) for verification. If a generic key identifier is provided (such as `PowerAuthSignatureKeyId.SERVER`), the function may fail when the current algorithm results in multiple key selections. You can relax this behavior by setting the `strict` parameter to `false`, but this is generally not recommended. In non-strict mode, an attacker could potentially remove or replace a stronger PQC signature with a weaker one without detection.
<!-- end box -->

## Creating Certificate Signing Request

The PowerAuth SDK can create a Certificate Signing Request (CSR) that can be used to request an X.509 certificate from a Public Key Infrastructure (PKI). The CSR contains a device public key generated by the SDK and is signed with the activation-bound private key.

The created CSR is returned in PEM format, including the `-----BEGIN CERTIFICATE REQUEST-----` and `-----END CERTIFICATE REQUEST-----` lines and newline characters (`\n`).

To create a CSR, use the following code:

```kotlin
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")
val keyIdentifier = PowerAuthSignatureKeyId.DEVICE_ML_DSA;

powerAuth.createCertificateSigningRequest(
    appContext, // Android context
    authentication, // authentication object
    mapOf( // subject's distinguished names (DN)
        Pair("CN", "wultra.com"),
        Pair("O", "Wultra"),
        Pair("C", "CZ")
    ),
    listOf( // subject's alternative names (SAN)
        "IP: 192.168.1.10",
        "email: admin@example.com"
    ),
    keyIdentifier, // Key Identifier
    object : ICreateCertificateSigningRequestListener {
        override fun onCreateCertificateSigningRequestSucceed(certificateSigningRequest: String) {
            Log.d("CSR", "CSR: ${certificateSigningRequest}")
            // Use the CSR
        }

        override fun onCreateCertificateSigningRequestFailed(throwable: Throwable) {
            // Handle error
        }
    }
)
```

<!-- begin box info -->
If the `PowerAuthSDK` instance is not configured for the legacy mode (that is, the algorithm is not `LEGACY_P256`), you can also use biometric authentication to create CSR.
<!-- end -->


## Getting Device Public Keys

Use the following code to retrieve device public keys associated with the activation:

```swift
try {
    val keys = exportDevicePublicKeys(PowerAuthDevicePublicKeyFormat.DER)
    for (key in keys) {
        if (key.keyType == PowerAuthSignatureKeyType.EC) {
            println("EC key algorithm: ${key.keyAlgorithm}")
            println("  X.509 key data: ${Base64.getEncoder().encodeToString(key.keyData)}")
        } else {
            println("ML-DSA key algorithm: ${key.keyAlgorithm}")
            println("       X.509 key data: ${Base64.getEncoder().encodeToString(key.keyData)}")
        }
    }
} catch (exception: PowerAuthErrorException) {
    // Fail, such as missing activation
}
```

Available format specifiers:

- `PowerAuthDevicePublicKeyFormat.DER` - The public key is exported in binary X.509 (DER) format.
- `PowerAuthDevicePublicKeyFormat.RAW` - The raw key format depends on the key type:
  - **EC keys**: The output is ASN.1 encoded, as defined in **ANSI X9.63**.
  - **ML-DSA keys**: The output contains the raw public key obtained via OpenSSL’s `EVP_PKEY_get_raw_public_key()`.

## Read Next

- [Password Change](Password-Change.md)
