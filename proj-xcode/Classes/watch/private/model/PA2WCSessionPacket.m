/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2WCSessionPacket_Success.h"
#import "PA2ErrorConstants.h"
#import "PA2PrivateMacros.h"

@implementation PA2WCSessionPacket

+ (PA2WCSessionPacket*) packetWithError:(NSError*)error
{
	PA2WCSessionPacket * packet = [[PA2WCSessionPacket alloc] init];
	packet.error = error;
	packet.target = PA2WCSessionPacket_RESPONSE_TARGET;
	return packet;
}

+ (PA2WCSessionPacket*) packetWithSuccess
{
	return [self packetWithSuccessCode:1];
}

+ (PA2WCSessionPacket*) packetWithSuccessCode:(NSInteger)code
{
	PA2WCSessionPacket * packet = [[PA2WCSessionPacket alloc] init];
	packet.target = PA2WCSessionPacket_RESPONSE_TARGET;
	packet.payload = [[PA2WCSessionPacket_Success alloc] initWithCode:code];
	return packet;
}


+ (PA2WCSessionPacket*) packetWithData:(id<PA2WCSessionPacketData>)data target:(NSString *)target
{
	PA2WCSessionPacket * packet = [[PA2WCSessionPacket alloc] init];
	packet.target = target;
	packet.payload = data;
	return packet;
}

- (NSDictionary*) toDictionary
{
	NSMutableDictionary * dict = [NSMutableDictionary dictionaryWithCapacity:8];
	
	dict[PA2WCSessionPacket_KEY_TARGET] = _target ? _target : PA2WCSessionPacket_RESPONSE_TARGET;
	if (_error) {
		dict[PA2WCSessionPacket_KEY_ERROR_CODE] = @(_error.code);
		dict[PA2WCSessionPacket_KEY_ERROR_DOM]  = _error.domain;
		NSString * desc = _error.localizedDescription;
		if (desc) {
			dict[PA2WCSessionPacket_KEY_ERROR_MSG] = desc;
		}
	} else if (_payload) {
		[_payload serializeToDictionary:dict];
	}
	return dict;
}

- (id) initWithDictionary:(NSDictionary*)dictionary
{
	self = [super init];
	if (self) {
		_sourceData = dictionary;
		_target = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_TARGET], NSString);
		if (!_target) {
			return nil;
		}
		NSNumber * errorCode = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_ERROR_CODE], NSNumber);
		if (errorCode != nil) {
			NSInteger ec = [errorCode integerValue];
			NSString * domain = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_ERROR_DOM], NSString);
			if (!domain) {
				domain = PA2ErrorDomain;
			}
			NSString * msg = PA2ObjectAs(dictionary[PA2WCSessionPacket_KEY_ERROR_MSG], NSString);
			NSDictionary * info = msg ? @{NSLocalizedDescriptionKey : msg } : nil;
			_error = [NSError errorWithDomain:domain code:ec userInfo:info];
		}
	}
	return self;
}

- (BOOL) deserializePayloadForClass:(Class)aClass
{
	if (!_error && _sourceData) {
		id instance = [[aClass alloc] initWithDictionary:_sourceData];
		if ([instance conformsToProtocol:@protocol(PA2WCSessionPacketData)]) {
			_payload = instance;
			return YES;
		}
	}
	return NO;
}

@end
