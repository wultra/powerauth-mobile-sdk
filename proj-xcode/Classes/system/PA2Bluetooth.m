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

#import "PA2Bluetooth.h"
#import "PA2Macros.h"
#import <CommonCrypto/CommonDigest.h>
#import "PA2Session.h"

NSString *const PA2BluetoothDomain = @"PA2BluetoothDomain";

NSUInteger const PA2ErrorBluetoothDeviceOff			= 1;
NSUInteger const PA2ErrorBluetoothUnauthorized		= 2;
NSUInteger const PA2ErrorBluetoothUnknownState		= 4;
NSUInteger const PA2ErrorBluetoothUnsupported		= 8;

NSUInteger const PA2BluetoothMaxFailCount			= 2; // at most 2 failures

@implementation PA2BluetoothContext

- (NSString *)description {
	return [NSString stringWithFormat:@"[identifier: %@, device name: %@, key: %@, salt: %@]",
			self.identifier,
			self.deviceName,
			[self.encryptionKey base64EncodedStringWithOptions:kNilOptions],
			[self.randomSalt base64EncodedStringWithOptions:kNilOptions]
			];
}

@end

@implementation PA2Bluetooth {
	CBCentralManager *_bluetoothManager;
	CBUUID *_serviceUuid;
	PA2BluetoothInitBlock _initCallback;
	CBPeripheral *_currentPeripheral;
	NSData *_salt;
	BOOL _disconnected;
	NSUInteger _failCount;
	__weak id<PA2BluetoothPresenceDelegate> _presenceDelegate;
	NSTimer *_timer;
	NSTimer *_discoverTimer;
}

#pragma mark - Helper Crypto Methods

- (NSData*) sha256:(NSData*)dataIn {
	NSMutableData *result = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(dataIn.bytes, (CC_LONG)dataIn.length,  result.mutableBytes);
	return result;
}

- (NSString *)hexadecimalString:(NSData*)data {
	if (data == nil) {
		return nil;
	}
	const unsigned char *dataBuffer = (const unsigned char *)[data bytes];
	if (!dataBuffer) {
		return nil;
	}
	NSUInteger length = [data length];
	NSMutableString *hexString = [NSMutableString stringWithCapacity:(length * 2)];
	for (int i = 0; i < length; i++) {
		[hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
	}
	return [NSString stringWithString:hexString];
}

- (NSData*)createRandomNSData:(NSUInteger)size {
	NSMutableData* theData = [NSMutableData dataWithCapacity:size];
	for (int i = 0; i < size / 4; i++) {
		u_int32_t randomBits = arc4random();
		[theData appendBytes:(void*)&randomBits length:4];
	}
	return theData;
}

#pragma mark - Initializer

- (instancetype)init {
	self = [super init];
	if (self) {
		dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
		_bluetoothManager = [[CBCentralManager alloc] initWithDelegate:self queue:queue];
		_serviceUuid = [CBUUID UUIDWithString:@"180A"];
		_disconnected = YES;
		_failCount = PA2BluetoothMaxFailCount;
	}
	return self;
}

+ (nullable instancetype)bluetoothWithCallback:(PA2BluetoothInitBlock)callback {
	PA2Bluetooth *inst = [[PA2Bluetooth alloc] init];
	[inst setCallback:callback];
	return inst;
}

- (void) setCallback:(PA2BluetoothInitBlock)callback {
	if (_initCallback != callback) {
		_initCallback = callback;
	}
}

#pragma mark - Bluetooth helpers

- (void) startRssiUpdateSchedule {
	if (_currentPeripheral != nil) {
		[_currentPeripheral readRSSI];
		if (_timer == nil || ![_timer isValid]) {
			_timer = [NSTimer timerWithTimeInterval:3.0 repeats:YES block:^(NSTimer * _Nonnull timer) {
				[_currentPeripheral readRSSI];
			}];
			[[NSRunLoop mainRunLoop] addTimer:_timer forMode:NSRunLoopCommonModes];
		}
	}
}

- (void) stopRssiUpdateSchedule {
	if (_timer != nil && [_timer isValid]) {
		[_timer invalidate];
	}
}

- (void) scanForDeviceWithIdentifier:(NSString*)identifier {
	NSArray *services = @[_serviceUuid];
	NSArray<CBPeripheral*> *peripherals = [_bluetoothManager retrieveConnectedPeripheralsWithServices:services];
	
	for (CBPeripheral *peripheral in peripherals) {
		peripheral.delegate = self;
		[_bluetoothManager connectPeripheral:peripheral options:nil];
		
		NSData *deviceIdData = [peripheral.identifier.UUIDString dataUsingEncoding:NSUTF8StringEncoding];
		NSData *deviceIdHash = [self sha256:deviceIdData];
		NSString *ident = [self hexadecimalString:deviceIdHash];
		
		if ([ident isEqual:identifier]) {
			_currentPeripheral = peripheral;
		} else {
			[_bluetoothManager cancelPeripheralConnection:peripheral];
		}
	}
}

- (void) startScanningForConnectedDevicesWithIdentifier:(NSString*)identifier {
	if (_discoverTimer == nil || ![_discoverTimer isValid]) {
		[self scanForDeviceWithIdentifier:identifier];
		_discoverTimer = [NSTimer timerWithTimeInterval:5.0 repeats:YES block:^(NSTimer * _Nonnull timer) {
			[self scanForDeviceWithIdentifier:identifier];
		}];
		[[NSRunLoop mainRunLoop] addTimer:_discoverTimer forMode:NSRunLoopCommonModes];
	}
}

- (void) stopScanningForConnectedDevices {
	if (_discoverTimer != nil && [_discoverTimer isValid]) {
		[_discoverTimer invalidate];
	}
}

- (double) calculateDistanceForRssi:(double)rssi {
	
	double txPower = 65.0; // guess - this gives nice values for RSSI < 50
	
	if (rssi == 0) {
		return -1.0; // if we cannot determine accuracy, return -1.
	}
	
	double ratio = rssi * 1.0 / txPower;
	if (ratio < 1.0) {
		return pow(ratio, 10.0);
	} else {
		return pow(ratio, 7.7095) * (0.89976) + 0.111;
	}
}

#pragma mark - CBCentralManagerDelegate

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
	switch ([central state]) {
		case CBCentralManagerStatePoweredOff: {
			if (_initCallback) {
				NSError *error = [NSError errorWithDomain:PA2BluetoothDomain code:PA2ErrorBluetoothDeviceOff userInfo:nil];
				_initCallback(error);
				_initCallback = nil;
			}
			break;
		}
		case CBCentralManagerStatePoweredOn: {
			if (_initCallback) {
				_initCallback(nil); // SUCCESS
				_initCallback = nil;
			}
			break;
		}
		case CBCentralManagerStateResetting: {
			break; // WAIT HERE, MAY BE CORRECTED
		}
		case CBCentralManagerStateUnauthorized: {
			if (_initCallback) {
				NSError *error = [NSError errorWithDomain:PA2BluetoothDomain code:PA2ErrorBluetoothUnauthorized userInfo:nil];
				_initCallback(error);
				_initCallback = nil;
			}
			break;
		}
		case CBCentralManagerStateUnknown: {
			if (_initCallback) {
				NSError *error = [NSError errorWithDomain:PA2BluetoothDomain code:PA2ErrorBluetoothUnknownState userInfo:nil];
				_initCallback(error);
				_initCallback = nil;
			}
			break;
		}
		case CBCentralManagerStateUnsupported: {
			if (_initCallback) {
				NSError *error = [NSError errorWithDomain:PA2BluetoothDomain code:PA2ErrorBluetoothUnsupported userInfo:nil];
				_initCallback(error);
				_initCallback = nil;
			}
			break;
		}
		default: {
			if (_initCallback) {
				NSError *error = [NSError errorWithDomain:PA2BluetoothDomain code:PA2ErrorBluetoothUnknownState userInfo:nil];
				_initCallback(error);
				_initCallback = nil;
			}
			break;
		}
	}
}

- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral {
	if ([peripheral.identifier.UUIDString isEqual:_currentPeripheral.identifier.UUIDString]) {
		PALog(@"RE-CONNECTED THE DEVICE");
		_currentPeripheral.delegate = self;
		[self stopScanningForConnectedDevices];
		[self startRssiUpdateSchedule];
	}
}

- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
	if ([peripheral.identifier.UUIDString isEqual:_currentPeripheral.identifier.UUIDString]) {
		PALog(@"DISCONNECTED THE DEVICE");
		_disconnected = YES;
		if (_presenceDelegate != nil && [_presenceDelegate respondsToSelector:@selector(bluetoothDidLoseContext)]) {
			[_presenceDelegate bluetoothDidLoseContext];
		}
		[self stopRssiUpdateSchedule];
		NSData *deviceIdData = [_currentPeripheral.identifier.UUIDString dataUsingEncoding:NSUTF8StringEncoding];
		NSData *deviceIdHash = [self sha256:deviceIdData];
		NSString *ident = [self hexadecimalString:deviceIdHash];
		[self startScanningForConnectedDevicesWithIdentifier:ident];
	}
}

#pragma mark - CBPeripheralManagerDelegate

- (void)peripheral:(CBPeripheral *)peripheral didReadRSSI:(NSNumber *)RSSI error:(NSError *)error {
	
	double distance = [self calculateDistanceForRssi:RSSI.doubleValue];
	
	if (_currentPeripheral != nil && [peripheral isEqual:_currentPeripheral]) {
		
		PALog(@"%@ - %@", _currentPeripheral.name, RSSI);
		
		if (distance > 20.0 && !_disconnected) { // Device is far, and not yet disconnected.
			if (_failCount > 0) { // Did this happen only once or twice?
				_failCount--;
				PALog(@"Device is far - %@ attempts to reconnect", @(_failCount));
			} else { // The device lost context.
				PALog(@"Device is far - disconnecting.");
				if (_presenceDelegate != nil && [_presenceDelegate respondsToSelector:@selector(bluetoothDidLoseContext)]) {
					[_presenceDelegate bluetoothDidLoseContext];
				}
				_disconnected = YES;
			}
		} else if (distance <= 2.0 && _disconnected) { // Device is disconnected, but it is back nearby.
			_failCount = PA2BluetoothMaxFailCount;
			PALog(@"Device is nearby - connecting.");
			if (_presenceDelegate != nil && [_presenceDelegate respondsToSelector:@selector(bluetoothDidDiscoverContextWithEncryptionKey:)]) {
				
				NSData *deviceIdData = [peripheral.identifier.UUIDString dataUsingEncoding:NSUTF8StringEncoding];
				NSMutableData *data = [[NSMutableData alloc] initWithData:deviceIdData];
				[data appendData:_salt];
				NSData *encryptionKey = [[self sha256:data] subdataWithRange:NSMakeRange(0, 16)];
				
				[_presenceDelegate bluetoothDidDiscoverContextWithEncryptionKey:encryptionKey];
			}
			_disconnected = NO;
		} else if (distance <= 20.0 && _failCount != PA2BluetoothMaxFailCount) { // Not any of the cases before, device is reasonably close, reset the fail count.
			PALog(@"Device is nearby - reseting fail count.");
			_failCount = PA2BluetoothMaxFailCount;
		} else {
			PALog(@"Device state unchanged in a significant way.");
		}
		
	}
}

#pragma mark - Public methods

- (void) scanDevicesWithCallback:(void(^)(NSArray<PA2BluetoothContext*>*))callback {
	
	NSArray *services = @[_serviceUuid];
	NSArray<CBPeripheral*> *peripherals = [_bluetoothManager retrieveConnectedPeripheralsWithServices:services];
	NSMutableArray<PA2BluetoothContext*> *result = [NSMutableArray array];
	
	for (CBPeripheral *peripheral in peripherals) {
		peripheral.delegate = self;
		NSData *deviceIdData = [peripheral.identifier.UUIDString dataUsingEncoding:NSUTF8StringEncoding];
		NSData *deviceIdHash = [self sha256:deviceIdData];
		NSString *identifier = [self hexadecimalString:deviceIdHash];
		
		NSData *salt = [self createRandomNSData:16];
		
		NSMutableData *data = [[NSMutableData alloc] initWithData:deviceIdData];
		[data appendData:salt];
		NSData *encryptionKey = [[self sha256:data] subdataWithRange:NSMakeRange(0, 16)];
		
		PA2BluetoothContext *context = [[PA2BluetoothContext alloc] init];
		context.identifier = identifier;
		context.deviceName = peripheral.name;
		context.encryptionKey = encryptionKey;
		context.randomSalt = salt;
		[result addObject:context];
	}
	
	callback(result);
	
}

- (void) establishBluetoothEncryptionKeyForIdentifier:(NSString *_Nullable)identifier
												 salt:(NSData *_Nullable)salt
									 presenceDelegate:(id<PA2BluetoothPresenceDelegate>)presenceDelegate {
	
	_salt = salt;
	_presenceDelegate = presenceDelegate;
	[self startScanningForConnectedDevicesWithIdentifier:identifier];
	
}

@end
