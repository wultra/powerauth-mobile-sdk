# Migration from 1.7.x to 1.8.x

PowerAuth Mobile SDK in version `1.8.0` provides the following improvements:

- Added support for simplified configuration. The SDK is now configured with using one Base64 encoded string instead of three separate values.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `1.5.0` and newer.

## Android

### API changes

- `PowerAuthConfiguration`
  - `Builder` constructor now supports only the simplified configuration. For example:
    ```java
    final PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
                "your-instance-id",
                "https://api.wultra.com/enrollment-server",
                "ARDDj6EB6iA...H9bMk8Ju3K1wmjbA=="
            ).build();
    ```
### Other changes

- TBA

## iOS & tvOS

### API changes

- `PowerAuthConfiguration` - class now supports only the simplified configuration.
  - Use new object constructor with all required parameters:
    ```swift
    let config = PowerAuthConfiguration(
        instanceId: "your-instance-id",
        baseEndpointUrl: "https://api.wultra.com/enrollment-server",
        configuration: "ARDDj6EB6iA...H9bMk8Ju3K1wmjbA=="
    )
    ```
  - Removed `applicationKey`, `applicationSecret`, `masterServerPublicKey` properties.
  - Constructor with no parameters is no longer supported.

### Other changes

- TBA

## iOS & tvOS App Extensions

### API changes

- TBA

## watchOS

### API changes

- TBA