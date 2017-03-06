/**
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

/** Class representing a new Bluetooth device context, returned when scanning for the new devices.
 */
@interface PA2BluetoothContext : NSObject

/** String uniquely identifying the device.
 
 In this particular implementation, it is a SHA256 of BLE device identifier provided by Core Bluetooth. Client application is expected to store this value in a keychain so that it can be used when establishing the context.
 */
@property (nonatomic, strong, nonnull) NSString *identifier;

/** Name of the BLE device.
 
 The client application is supposed to display this as a visual identifier of the device.
 */
@property (nonatomic, strong, nonnull) NSString *deviceName;

/** Encryption key derived from the BLE device identifier provided by Core Bluetooth.
 
 In this particular implementation, the implementation uses SHA256 of identifier value in combination with 16B random salt (stored on the device), like this:
 
 `encryptionKey = SHA256(context.identifier + randomSalt)`
 
 Warning: Client application must not store this key in persistent memory.
 
 */
@property (nonatomic, strong, nonnull) NSData *encryptionKey;

/** Random bytes used as a salt for deriving encryption key.
 
 Client application is expected to store this value in a keychain so that it can be used when establishing the context.
 */
@property (nonatomic, strong, nonnull) NSData *randomSalt;

@end

typedef void(^PA2BluetoothInitBlock)(NSError * _Nullable);

/** Delegate for Bluetooth device context callbacks
 */
@protocol PA2BluetoothPresenceDelegate <NSObject>

@optional
/** Callback for the situation an encryption key is found.
 
 The client application is expected to store the key and set it to the primary PowerAuthSDK instance.
 
 @param encryptionKey NSData representing the key used for encryption (as EEK).
 */
- (void) bluetoothDidDiscoverContextWithEncryptionKey:(NSData *_Nullable)encryptionKey;

/** Callback called when the bluetooth device context is lost.
 
 The client application is expected to drop the stored key and sign user out of the application.
 */
- (void) bluetoothDidLoseContext;
@end

/** The primary class used for interacting with the Bluetooth device context.
 */
@interface PA2Bluetooth : NSObject <CBCentralManagerDelegate, CBPeripheralDelegate>

/** Initialize a new instance and call a callback when the Bluetooth HW is ready or the HW cannot be used.
 
 @param callback Callback called upon updating the Bluetooth HW status.
 @return New instance of a PA2Bluetooth class.
 */
+ (nullable instancetype) bluetoothWithCallback:(nullable PA2BluetoothInitBlock)callback;

/** Scan for devices that are nearby.
 
 @param callback Callback called upon updating the Bluetooth device list with a snapshot result.
 */
- (void) scanDevicesWithCallback:(nonnull void(^)(NSArray<PA2BluetoothContext*> *_Nullable devices))callback;

/** Starts the scanning process that establishes the encryption key for given device identifier.
 
 @param identifier from `PA2BluetoothContext`.
 @param salt from `PA2BluetoothContext`.
 */
- (void) establishBluetoothEncryptionKeyForIdentifier:(NSString *_Nullable)identifier
												 salt:(NSData *_Nullable)salt
									 presenceDelegate:(nullable id<PA2BluetoothPresenceDelegate>)presenceDelegate;

@end
