/**
 * Copyright 2018 Lime - HighTech Solutions s.r.o.
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

#import "PA2WatchRemoteTokenProvider.h"
#import "PA2WCSessionManager+Private.h"
#import "PA2WCSessionPacket_TokenData.h"

#import "PA2PrivateMacros.h"
#import "PA2ErrorConstants.h"
#import "PowerAuthConfiguration.h"


@implementation PA2WatchRemoteTokenProvider
{
	PowerAuthConfiguration * _configuration;
	NSString * _target;
}


#pragma mark - Cancellable task

/*
 Cancellable task
 
 The any-kind of cancellable task is required by the PA2PrivateRemoteTokenProvider.
 To fulfill this contract, we're using a simple NSMutableData as cancel request
 value holder.
 
 If the task is cancelled, then the execution is is completed as usual, but
 the completion block to the user's code is not called.
 */

static id _TaskMakeNew()
{
	return [NSMutableData dataWithLength:1];
}

static BOOL _TaskIsCancelled(id task)
{
	NSMutableData * data = PA2ObjectAs(task, NSMutableData);
	if (data.length == 1) {
		const char * bytes = (const char *)data.bytes;
		return bytes[0] != 0;
	}
	return NO;
}

static void _TaskCancel(id task)
{
	NSMutableData * data = PA2ObjectAs(task, NSMutableData);
	if (data.length == 1) {
		char * bytes = (char *)data.mutableBytes;
		bytes[0] = 1;
	}
}


#pragma mark - PA2PrivateRemoteTokenProvider

- (void) prepareInstanceForConfiguration:(nonnull PowerAuthConfiguration*)configuration
{
	_configuration = configuration;
	_target = [PA2WCSessionPacket_TOKEN_TARGET stringByAppendingString:_configuration.instanceId];
}


- (nullable PowerAuthTokenStoreTask) requestTokenWithName:(nonnull NSString*)name
										   authentication:(nonnull PowerAuthAuthentication*)authentication
											   completion:(nonnull void(^)(PA2PrivateTokenData * _Nullable tokenData, NSError * _Nullable error))completion
{
	//
	// Remote request for token, with using WatchConnectivity framework
	//
	PA2WCSessionPacket_TokenData * requestData = [[PA2WCSessionPacket_TokenData alloc] init];
	requestData.command   = PA2WCSessionPacket_CMD_TOKEN_GET;
	requestData.tokenName = name;
	PA2WCSessionPacket * packet = [PA2WCSessionPacket packetWithData:requestData target:_target];
	
	id task = _TaskMakeNew();
	PA2WCSessionManager * manager = [PA2WCSessionManager sharedInstance];
	[manager sendPacketWithResponse:packet responseClass:requestData.class completion:^(PA2WCSessionPacket *response, NSError *error) {
		//
		if (_TaskIsCancelled(task)) {
			return;
		}
		//
		PA2PrivateTokenData * tokenData = nil;
		if (!error) {
			PA2WCSessionPacket_TokenData * responseData = PA2ObjectAs(response.payload, PA2WCSessionPacket_TokenData);
			if ([responseData.command isEqualToString:PA2WCSessionPacket_CMD_TOKEN_PUT]) {
				tokenData = [PA2PrivateTokenData deserializeWithData:responseData.tokenData];
				if (!tokenData) {
					error = PA2MakeError(PA2ErrorCodeWatchConnectivity, @"PA2WatchRemoteTokenProvider: Wront token data received.");
				}
			} else {
				error = PA2MakeError(PA2ErrorCodeWatchConnectivity, @"PA2WatchRemoteTokenProvider: Wront command received.");
			}
		}
		completion(tokenData, error);
	}];
	return task;
}

- (nullable PowerAuthTokenStoreTask) removeTokenData:(nonnull PA2PrivateTokenData*)tokenData
										  completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion
{
	completion(NO, PA2MakeError(PA2ErrorCodeInvalidToken, @"Remote token removal is unsupported operation"));
	return nil;
}

- (void) cancelTask:(nullable PowerAuthTokenStoreTask)task
{
	_TaskCancel(task);
}

@end
