/*
 * Copyright 2022 Wultra s.r.o.
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2CreateTokenTask.h"
#import "PA2PrivateMacros.h"

@implementation PA2CreateTokenTask
{
	id<PA2PrivateRemoteTokenProvider> _tokenProvider;
	id<PowerAuthPrivateTokenStore> _tokenStore;
	NSString * _tokenName;
	NSString * _activationId;
	PowerAuthAuthentication * _authentication;
	
	PA2PrivateTokenData * _privateTokenData;
}

- (id) initWithProvider:(id<PA2PrivateRemoteTokenProvider>)provider
			 tokenStore:(id<PowerAuthPrivateTokenStore>)tokenStore
		 authentication:(PowerAuthAuthentication*)authentication
		   activationId:(NSString*)activationId
			  tokenName:(NSString*)tokenName
			 sharedLock:(id<NSLocking>)sharedLock
{
	self = [super initWithSharedLock:sharedLock];
	if (self) {
		_tokenProvider = provider;
		_tokenStore = tokenStore;
		_activationId = activationId;
		_tokenName = tokenName;
		_authentication = authentication;
	}
	return self;
}

- (void) onTaskStart
{
	[super onTaskStart];
	
	_privateTokenData = nil;
	id<PowerAuthOperationTask> task = [_tokenProvider requestTokenWithName:_tokenName authentication:_authentication completion:^(PA2PrivateTokenData * tokenData, NSError * error) {
		PowerAuthToken * token;
		if (tokenData) {
			tokenData.activationIdentifier = _activationId;
			token = [[PowerAuthToken alloc] initWithStore:_tokenStore data:tokenData];
			_privateTokenData = tokenData;
		} else {
			token = nil;
		}
		[self complete:token error:error];
	}];
	if (task) {
		[self addCancelableOperation:task];
	} else {
		[self complete:nil error:PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"Failed to get token from remote provider.")];
	}
}

- (void) onTaskCancel
{
	[super onTaskCancel];
	
	[_tokenStore removeCreateTokenTask:_tokenName];
}

- (void) onTaskComplete
{
	[super onTaskComplete];
	
	if (_privateTokenData) {
		[_tokenStore storeTokenData:_privateTokenData];
	}
	[_tokenStore removeCreateTokenTask:_tokenName];
}
@end
