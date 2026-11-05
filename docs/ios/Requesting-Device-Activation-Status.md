# Requesting Device Activation Status

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB iOS href=../PowerAuth-SDK-for-iOS -->

To obtain detailed activation status information, use the following code:

```swift
// Check if there is some activation on the device
if powerAuthSDK.hasValidActivation() {

    // If there is an activation on the device, check the status with the server
    powerAuthSDK.fetchActivationStatus() { (status, error) in

        // If no error occurred, process the status
        if let status = status {
            // Activation states are explained in detail in "Activation states" chapter below
            switch status.state {
            case .pendingCommit:
                print("Waiting for commit")
            case .active:
                print("Activation is active")
            case .blocked:
                print("Activation is blocked")
            case .removed:
                print("Activation is no longer valid")
                powerAuthSDK.removeActivationLocal()
            case .deadlock:
                print("Activation is technically blocked")
                powerAuthSDK.removeActivationLocal()
            default:
                print("Unknown state")
            }

            // Failed login attempts, remaining = max - current
            let currentFailCount = status.failCount
            let maxAllowedFailCount = status.maxFailCount
            let remainingFailCount = status.remainingAttempts

            if let customObject = status.customObject {
                // Custom object contains any proprietary server-specific data
            }
            if status.isProtocolUpgradeAvailable {
                // Upgrade to new protocol version is available
            }
            if let unblockTime = status.blockExpirationTime {
                // Activation is temporarily blocked. Use synchronized time to compare
                // the timestamp received from the server.
                let currentTime = powerAuthSDK.timeSynchronizationService.currentTime()
                let remainingBlockTime = unblockTime.timeIntervalSince1970 - currentTime
                if remainingBlockTime > 0 {
                    print("Seconds to activation unblock \(remainingBlockTime)")
                }
            }
        } else {
            // Network error occurred, report it to the user
        }
    }

} else {
    // No activation present on the device
}
```

## Activation states

This chapter explains activation states in detail. To get more information about activation lifecycle, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

### `PowerAuthActivationState.pendingCommit`

The activation record is created, and the key exchange between the client and server has already taken place, but the activation record on the server requires additional approval before it can be used. This approval is typically performed through an internet banking platform by the client or handled by an authorized representative in a back office system.

### `PowerAuthActivationState.active`

The activation record is created and active. It is ready to be used for typical use-cases, such as generating authentication codes.

### `PowerAuthActivationState.blocked`

The activation record is blocked and cannot be used for most use-cases, such as generating authentication codes. While it can be unblocked and activated again, the unblock process cannot be performed locally on the mobile device and requires intervention through an external system, such as internet banking or a back office platform.

### `PowerAuthActivationState.removed`

The activation record is removed and permanently blocked. It cannot be used for generating authentication codes or ever unblocked. You can inform user about this situation and remove the activation locally.

### `PowerAuthActivationState.deadlock`

The local activation is technically blocked and can no longer be used for authentication code calculations. You can inform the user about this situation and remove the activation locally.

The reason why the mobile client is no longer capable of calculating valid authentication codes is that the logical counter is out of sync between the client and the server. This may happen only if the mobile client calculates too many PowerAuth authentication codes without subsequent validation on the server. For example:

- If your application repeatedly constructs HTTP requests with a PowerAuth authentication code while the network is unreachable.
- If your application repeatedly creates authentication tokens while the network is unreachable. For example, when trying to register for push notifications in the background, without user interaction.
- If you calculate too many offline authentication codes without subsequent validation.

In rare situations, this may also happen in development or testing environments, where you’re able to restore the state of the activation on the server from a snapshot.

## Read Next

- [Data Signing](Data-Signing.md)
