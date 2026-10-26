# Synchronized Time

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

The PowerAuth mobile SDK internally uses time synchronized with the PowerAuth Server for its cryptographic functions, such as [End-To-End Encryption](End-To-End-Encryption.md) or [Token-Based Authentication](Token-Based-Authentication.md). The synchronized time can also be beneficial for your application. For example, if you want to display a time-sensitive message or countdown to your users, you can take advantage of this service.

Use the following code to get the service responsible for the time synchronization: 

```kotlin
val timeService = powerAuthSDK.timeSynchronizationService
```

## Automatic Time Synchronization

The time is synchronized automatically in the following situations:

- After an activation is created
- After getting an activation status
- After receiving any response encrypted with our End-To-End Encryption scheme

The time synchronization is reset automatically once your application transitions from the background to the foreground.

## Manually Synchronize Time

Use the following code to synchronize the time manually:

```kotlin
val task = timeService.synchronizeTime(object: ITimeSynchronizationListener {
    override fun onTimeSynchronizationSucceeded() {
        // Synchronization succeeded
    }

    override fun onTimeSynchronizationFailed(t: Throwable) {
        // Synchronization failed
    }
})
```

## Get Synchronized Time

To get the synchronized time, use the following code:

```kotlin
if (timeService.isTimeSynchronized) {
    // get synchronized timestamp in milliseconds, since 1.1.1970
    val timestamp = timeService.currentTime
} else {
    // Time is not synchronized yet. If you call currentTime then 
    // the returned timestamp is similar to System.currentTimeMillis()
    val timestamp = timeService.currentTime
}
```

The time service provides additional information about time, such as how precisely the time is synchronized with the server:

```kotlin
if (timeService.isTimeSynchronized) {
    val precision = timeService.localTimeAdjustmentPrecision
    println("Time is now synchronized with precision ${precision}")
}
```

The precision value represents a maximum absolute deviation of synchronized time against the actual time on the server. For example, a value `500` means that the time provided by the `currentTime` method may be 0.5 seconds ahead or behind the actual time on the server. If the precision is not sufficient for your purpose, for example, if you need to display a real-time countdown in your application, then try to synchronize the time manually. The precision basically depends on how quickly is the synchronization response received and processed from the server. A faster response results in higher precision.

## Read Next

- [Common SDK Tasks](Common-SDK-Tasks.md)
