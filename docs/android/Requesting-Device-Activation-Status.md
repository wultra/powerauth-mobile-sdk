# Requesting Device Activation Status

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

To obtain detailed activation status information, use the following code:

```kotlin
// Check if there is some activation on the device
if (powerAuthSDK.hasValidActivation()) {
    // If there is an activation on the device, check the status with server
    powerAuthSDK.fetchActivationStatusWithCallback(context, object: IActivationStatusListener {
        override fun onActivationStatusSucceed(status: PowerAuthActivationStatus) {
            // Activation states are explained in detail in "Activation states" chapter below
            when (status.state) {
                PowerAuthActivationState.PENDING_COMMIT ->
                    Log.i(TAG, "Waiting for commit")
                PowerAuthActivationState.ACTIVE ->
                    Log.i(TAG, "Activation is active")
                PowerAuthActivationState.BLOCKED ->
                    Log.i(TAG, "Activation is blocked")
                PowerAuthActivationState.REMOVED -> {
                    Log.i(TAG, "Activation is no longer valid")
                    powerAuthSDK.removeActivationLocal(context)
                }
                PowerAuthActivationState.DEADLOCK -> {
                    Log.i(TAG, "Activation is technically blocked")
                    powerAuthSDK.removeActivationLocal(context)
                }
                else -> Log.i(TAG, "Unknown state")
            }

            // Failed login attempts, remaining = max - current
            val currentFailCount: Int = status.failCount
            val maxAllowedFailCount: Int = status.maxFailCount
            val remainingFailCount: Int = status.remainingAttempts
            if (status.customObject != null) {
                // Custom object contains any proprietary server specific data
            }
            if (status.isProtocolUpgradeAvailable) {
                // Upgrade to new protocol is available
            }
            val blockExpirationTime = status.blockExpirationTime
            if (blockExpirationTime != null) {
                // Activation is temporarily blocked. Use synchronized time to compare
                // the timestamp received from the server.
                val currentTime = powerAuthSDK.timeSynchronizationService.currentTime
                val remainingBlockTime = blockExpirationTime - currentTime
                if (remainingBlockTime > 0) {
                    Log.i(TAG, "Milliseconds to activation unblock ${remainingBlockTime}")
                }
            }
        }

        override fun onActivationStatusFailed(t: Throwable) {
            // Network error occurred, report it to the user
        }
    })
} else {
    // No activation present on device
}
```

Note that the status fetch may fail at an unrecoverable error `PowerAuthErrorCodes.PROTOCOL_UPGRADE`, meaning that it's not possible to upgrade the PowerAuth protocol to a newer version. In this case, it's recommended to [remove the activation locally](Device-Activation-Removal.md).

## Activation states

This chapter explains activation states in detail. To get more information about activation lifecycle, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

### `PowerAuthActivationState.CREATED`

The activation record is created using an external channel, such as the Internet banking, but the key exchange between the client and server did not happen yet. This state is never reported to the mobile client.

### `PowerAuthActivationState.PENDING_COMMIT`

The activation record is created, and the key exchange between the client and server has already taken place, but the activation record on the server requires additional approval before it can be used. This approval is typically performed through an internet banking platform by the client or handled by an authorized representative in a back office system.

### `PowerAuthActivationState.ACTIVE`

The activation record is created and active. It is ready to be used for typical use-cases, such as generating authentication codes.

### `PowerAuthActivationState.BLOCKED`

The activation record is blocked and cannot be used for most use-cases, such as generating authentication codes. While it can be unblocked and activated again, the unblock process cannot be performed locally on the mobile device and requires intervention through an external system, such as internet banking or a back office platform.

### `PowerAuthActivationState.REMOVED`

The activation record is removed and permanently blocked. It cannot be used for generating authentication codes or ever unblocked. You can inform user about this situation and remove the activation locally.

### `PowerAuthActivationState.DEADLOCK`

The local activation is technically blocked and can no longer be used for authentication code calculations. You can inform the user about this situation and remove the activation locally.

The reason why the mobile client is no longer capable of calculating valid authentication codes is that the logical counter is out of sync between the client and the server. This may happen only if the mobile client calculates too many PowerAuth authentication codes without subsequent validation on the server. For example:

- If your application repeatedly constructs HTTP requests with a PowerAuth authentication header while the network is unreachable.
- If your application repeatedly creates authentication tokens while the network is unreachable. For example, when trying to register for push notifications in the background, without user interaction.
- If you calculate too many offline authentication codes without subsequent validation.

In rare situations, this may also happen in development or testing environments, where you’re able to restore the state of the activation on the server from a snapshot.

## Read Next

- [Data Signing](Data-Signing.md)
