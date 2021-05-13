/**
 * Copyright 2021 Wultra s.r.o.
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

#import <PowerAuth2/PowerAuthToken.h>

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

/**
 The WatchSupport category provides simple interface for sending tokens to paired Apple Watch.
 Please read our integration guide (https://github.com/wultra/powerauth-mobile-sdk/docs/PowerAuth-SDK-for-watchOS.md)
 before you start using this interface in your application.
 */
@interface PowerAuthToken (WatchSupport)

/**
 Sends this token to the paired Apple Watch. The watch application must be installed on the device.
 The token transmission is performed with using `WCSession.transferUserInfo()` method, so the token will be
 available when IOS decide to transfer that data to the Apple Watch.
 
 Returns YES if transfer has been properly sheduled, or NO if WCSession is not ready for
 such transmission. Check `PA2WCSessionManager.validSession` documentation for details.
 */
- (BOOL) sendToWatch;

/**
 Sends this token to the paired Apple Watch. The watch application must be installed on the device.
 The token transmission is performed immediately with using `WCSession.sendMessageData(..)` method,
 so the Apple Watch has to be reachable in the time of the call.
 */
- (void) sendToWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion;

/**
 Removes this token from paired Apple Watch. The watch application must be installed on the device.
 The request transmission is performed with using `WCSession.transferUserInfo()` method, so the token will be
 removed when IOS decide to transfer that data to the Apple Watch.
 
 Note that you can call this method also when the associated token store has no longer a valid session.
 This behavior gives you an opportunity to perform your cleanup also after the session has been invalidated.
 
 Returns YES if transfer has been properly sheduled, or NO if WCSession is not ready for
 such transmission. Check `PA2WCSessionManager.validSession` documentation for details.
 */
- (BOOL) removeFromWatch;

/**
 Removes this token from paired Apple Watch. The watch application must be installed on the device.
 The token transmission is performed immediately with using `WCSession.sendMessageData(..)` method,
 so the Apple Watch has to be reachable in the time of the call.
 
 Note that you can call this method also when the associated token store has no longer a valid session.
 This behavior gives you an opportunity to perform your cleanup also after the session has been invalidated.
 */
- (void) removeFromWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion;

@end

// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
