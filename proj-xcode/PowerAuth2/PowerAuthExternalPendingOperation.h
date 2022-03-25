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

#import <PowerAuth2/PowerAuthMacros.h>

/**
 The `PowerAuthExternalPendingOperationType` enum defines types of operation
 started in another application that share activation data.
 */
typedef NS_ENUM(NSInteger, PowerAuthExternalPendingOperationType) {
	/**
	 Another application started an activation process. If you get this value,
	 then the recommended action is to instruct the user to switch to the application that
	 started the activation.
	 */
	PowerAuthExternalPendingOperationType_Activation  = 1,
	/**
	 Another application is working on the protocol upgrade task. If you get this value,
	 then the recommended action is to instruct the user to switch to the application that
	 does the protocol upgrade.
	 */
	PowerAuthExternalPendingOperationType_ProtocolUpgrade  = 2,
};

/**
 The `PowerAuthExternalPendingOperation` class contains data that can identify an external
 application that started the critical operation.
 */
@interface PowerAuthExternalPendingOperation : NSObject
/**
 Type of operation running in another application.
 */
@property (nonatomic, readonly) PowerAuthExternalPendingOperationType externalOperationType;
/**
 Identifier of external application that started the operation. This is the same identifier
 you provided to `PowerAuthSharingConfiguration` during the PowerAuthSDK initialization.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * externalApplicationId;

@end
