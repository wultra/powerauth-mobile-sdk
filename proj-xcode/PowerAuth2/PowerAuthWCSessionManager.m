/**
 * Copyright 2026 Wultra s.r.o.
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .

#import "PowerAuthWCSessionManager.h"

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

#import "PowerAuthErrorConstants.h"
#import "PowerAuthLog.h"

#import "PowerAuthWCSessionManager+Private.h"
#import "PA2PrivateMacros.h"
#import "PA2WCSessionPacket.h"
#import "PA2WeakArray.h"

@implementation PowerAuthWCSessionManager
{
    dispatch_semaphore_t _lock;
    WCSession * _session;
    PA2WeakArray<id<PA2WCSessionDataHandler>> * _dataHandlers;
    NSMutableArray<id<PA2WCSessionDataHandler>> * _fallbackDataHandlers;
}

#pragma mark - Init & Validate session

// Declaration of glue function which has to register all default services to the session manager.
PA2_EXTERN_C void PA2WCSessionManager_RegisterDefaultHandlers(PowerAuthWCSessionManager * sessionManager);

+ (PowerAuthWCSessionManager*) sharedInstance
{
    static dispatch_once_t onceToken;
    static PowerAuthWCSessionManager * _instance;
    dispatch_once(&onceToken, ^{
        _instance = [[PowerAuthWCSessionManager alloc] init];
        PA2WCSessionManager_RegisterDefaultHandlers(_instance);
    });
    return _instance;
}

static WCSession * _PrepareSession(void);
static WCSession * _ValidateSession(WCSession * session);

- (id) init
{
    self = [super init];
    if (self) {
        _lock = dispatch_semaphore_create(1);
        _session = _PrepareSession();
    }
    return self;
}

- (WCSession *) validSession
{
    return _ValidateSession(_session);
}

#pragma mark - Thread safety

/**
 Prepares runtime data required by this class. We're initializing those objects only
 on demand, when the first token is being accessed.
 */
static void _prepareInstance(PowerAuthWCSessionManager * obj)
{
    obj->_dataHandlers = [[PA2WeakArray alloc] initWithCapacity:8];
    obj->_fallbackDataHandlers = [NSMutableArray arrayWithCapacity:2];
}

/**
 A simple replacement for @synchronized() construct.
 This version of function returns object returned from the block.
 */
static id _synchronized(PowerAuthWCSessionManager * obj, id(^block)(void))
{
    dispatch_semaphore_wait(obj->_lock, DISPATCH_TIME_FOREVER);
    if (nil == obj->_dataHandlers) {
        _prepareInstance(obj);
    }
    id result = block();
    dispatch_semaphore_signal(obj->_lock);
    return result;
}

/**
 A simple replacement for @synchronized() construct.
 This version of function has no return value.
 */
static void _synchronizedVoid(PowerAuthWCSessionManager  * obj, void(^block)(void))
{
    dispatch_semaphore_wait(obj->_lock, DISPATCH_TIME_FOREVER);
    if (nil == obj->_dataHandlers) {
        _prepareInstance(obj);
    }
    block();
    dispatch_semaphore_signal(obj->_lock);
}


#pragma mark - Helper functions

static const char  _HeaderMagic[] = { 'P', 'A', 'w', 'c' };
static const char  _HeaderVersion = '2';
#define _MagicSize   sizeof(_HeaderMagic)
#define _HeaderSize  (_MagicSize + 1)

static PA2WCSessionPacket * _DeserializePacket(NSData * data, Class payloadClass, BOOL* failure)
{
    // Validate minimal length of data
    if (data.length < _HeaderSize + 12) {
        *failure = NO;
        return nil;
    }
    // ... and the magic constant at the beginning
    const char * dataBytes = data.bytes;
    if (memcmp(dataBytes, _HeaderMagic, _MagicSize)) {
        *failure = NO;
        return nil;
    }
    
    // We can process the response after this point.
    
    // Compare versions
    if (dataBytes[_MagicSize] != _HeaderVersion) {
        // Reply with a special packet with identical version as we received. This guarantees that another side is able to process this error.
        *failure = YES;
        NSString * message = @"PA2WCSessionManager: PowerAuth Mobile SDK and Watch SDK are not compatible.";
        PA2WCSessionPacket * packet = [PA2WCSessionPacket packetWithError:PA2MakeError(PowerAuthErrorCode_WatchConnectivity, message)];
        packet.customPacketVersion = dataBytes[_MagicSize];
        return packet;
    }
    
    // ... the rest of data should contain valid JSON
    NSData * jsonData = [data subdataWithRange:NSMakeRange(_HeaderSize, data.length - _HeaderSize)];
    NSError * error = nil;
    NSDictionary * root = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error], NSDictionary);
    if (!root) {
        *failure = YES;
        return [PA2WCSessionPacket packetWithError:PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: Invalid payload. Failed to deserialize JSON.")];
    }
    // Construct packet for further investigation
    PA2WCSessionPacket * packet = [[PA2WCSessionPacket alloc] initWithDictionary:root];
    if (packet) {
        if (payloadClass != Nil && !packet.error) {
            // Process payload only when class is known and there's no error in the packet.
            if ([payloadClass conformsToProtocol:@protocol(PA2WCSessionPacketData)]) {
                id<PA2WCSessionPacketData> payload = [[payloadClass alloc] initWithDictionary:root];
                if ([payload validatePacketData]) {
                    packet.payload = payload;
                } else {
                    NSString * message = [NSString stringWithFormat:@"PA2WCSessionManager: Invalid payload. %@ class is expected.", NSStringFromClass(payloadClass)];
                    error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, message);
                }
            } else {
                error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: Invalid class provided for payload response.");
            }
        }
    } else {
        error = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: Invalid packet received.");
    }
    if (error) {
        *failure = YES;
        return [PA2WCSessionPacket packetWithError:error];
    }
    *failure = NO;
    return packet;
}

static NSData * _SerializePacket(PA2WCSessionPacket * packet)
{
    NSDictionary * dict = [packet toDictionary];
    if (!dict) {
        PowerAuthLog(@"PA2WCSessionManager: Cannot serialize packet to dictionary.");
        return nil;
    }
    NSData * JSONData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:NULL];
    if (!JSONData) {
        PowerAuthLog(@"PA2WCSessionManager: Cannot serialize packet to JSON.");
        return nil;
    }
    // Prepare the packet version. If not set, then use the default version.
    char packetVersion = packet.customPacketVersion;
    if (!packetVersion) {
        packetVersion = _HeaderVersion;
    }
    NSMutableData * data = [NSMutableData dataWithCapacity:_HeaderSize + JSONData.length];
    [data appendBytes:_HeaderMagic length:_MagicSize];
    [data appendBytes:&packetVersion length:1];
    [data appendData:JSONData];
    return data;
}


#pragma mark - Message processing

- (BOOL) processReceivedMessageData:(nonnull NSData *)data
                       replyHandler:(void (^_Nullable)(NSData * _Nonnull reply))replyHandler
{
    PA2WCSessionDataHandlerResponse * response = nil;
    do {
        BOOL failure;
        PA2WCSessionPacket * packet = _DeserializePacket(data, Nil, &failure);
        if (!packet) {
            // Quick return, we don't understand this data
            return NO;
        }
        if (failure) {
            // Incoming packet processing raised an error. This is already the response.
            response = [PA2WCSessionDataHandlerResponse responseWithPacket:packet];
            break;
        }
        //
        NSString * target = packet.target;
        if ([target isEqualToString:PA2WCSessionPacket_RESPONSE_TARGET]) {
            response = [PA2WCSessionDataHandlerResponse responseWithErrorMessage:@"PA2WCSessionManager: Requests with response target are not allowed."];
            break;
        }
        // Look for handler
        id<PA2WCSessionDataHandler> handler = [self handlerForPacket:packet];
        if (!handler) {
            response = [PA2WCSessionDataHandlerResponse responseWithErrorMessage:
                            [NSString stringWithFormat:@"PA2WCSessionManager: Unable to handle request for target '%@'.", target]];
            break;
        }
        // ...and finally get the response
        packet.requestWithoutReplyHandler = replyHandler == nil;
        response = [handler sessionManager:self responseForPacket:packet];
        if (!response) {
            response = [PA2WCSessionDataHandlerResponse responseWithErrorMessage:
                            [NSString stringWithFormat:@"PA2WCSessionManager: Failed to create response for target '%@'.", target]];
        }
        
    } while (false);
    
    // Send response back, if packet is already present
    PA2WCSessionPacket * responsePacket = response.responsePacket;
    if (!responsePacket) {
        // Delayed completion
        [response setCompletionCallback:^(PA2WCSessionPacket *responsePacket) {
            [self sendResponsePacket:responsePacket replyHandler:replyHandler];
        }];
    } else {
        [self sendResponsePacket:responsePacket replyHandler:replyHandler];
    }
    return YES;
}

- (void) sendResponsePacket:(nonnull PA2WCSessionPacket *)responsePacket
               replyHandler:(void (^_Nullable)(NSData * _Nonnull reply))replyHandler
{
    if (replyHandler) {
        replyHandler(_SerializePacket(responsePacket));
    } else if (responsePacket.sendLazyResponseIfPossible) {
        [self sendPacket:responsePacket];
    } else {
        PowerAuthLog(@"PowerAuthWCSessionManager: Dropping response for fire-and-forget request because no reply handler is available.");
    }
}

- (BOOL) processReceivedUserInfo:(NSDictionary<NSString *,id> *)userInfo
{
    NSData * messageData = PA2ObjectAs(userInfo[PA2WCSessionPacket_USER_INFO_KEY], NSData);
    if (!messageData) {
        return NO;  // Not our message
    }
    return [self processReceivedMessageData:messageData replyHandler:nil];
}

@end



#pragma mark - Private interface -

@implementation PowerAuthWCSessionManager (Private)

#pragma mark - Handler registry

- (void) registerDataHandler:(id<PA2WCSessionDataHandler>)handler
{
    _synchronizedVoid(self, ^{
        [_dataHandlers addWeakObject:handler];
    });
}

- (void) unregisterDataHandler:(id<PA2WCSessionDataHandler>)handler
{
    _synchronizedVoid(self, ^{
        [_dataHandlers removeWeakObject:handler];
    });
}

- (id<PA2WCSessionDataHandler>) handlerForPacket:(PA2WCSessionPacket *)packet
{
    return _synchronized(self, ^id{
        id<PA2WCSessionDataHandler> handler = [_dataHandlers findObjectUsingBlock:^BOOL(id<PA2WCSessionDataHandler> item) {
            return [item canProcessPacket:packet];
        }];
        if (nil == handler) {
            for (id<PA2WCSessionDataHandler> item in _fallbackDataHandlers) {
                if ([item canProcessPacket:packet]) {
                    handler = item;
                    break;
                }
            }
        }
        return handler;
    });
}

- (void) registerFallbackDataHandler:(id<PA2WCSessionDataHandler>)handler
{
    _synchronizedVoid(self, ^{
        [_fallbackDataHandlers addObject:handler];
    });
}

#pragma mark - Sending data

- (void) sendPacket:(PA2WCSessionPacket*)packet
{
    [self sendImpl:packet withResponse:NO responseClass:Nil completion:nil];
}

- (void) sendPacketWithResponse:(PA2WCSessionPacket*)packet
                  responseClass:(Class)responseClass
                     completion:(void(^)(PA2WCSessionPacket * response, NSError * error))completion
{
    [self sendImpl:packet withResponse:YES responseClass:responseClass completion:completion];
}

- (void) sendImpl:(PA2WCSessionPacket*)request
     withResponse:(BOOL)withResponse
    responseClass:(Class)responseClass
       completion:(void(^)(PA2WCSessionPacket * response, NSError * error))completion
{
    // Validate input
    if (withResponse && (completion == nil)) {
        PowerAuthLog(@"PA2WCSessionManager: Response is required but completion block is missing.");
        return;
    }
    
    if (!request) {
        if (completion) {
            completion(nil, PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: Missing request packet in send method."));
        }
        return;
    }
    
    // Serialize packet
    NSData * requestData = _SerializePacket(request);
    if (!requestData) {
        if (completion) {
            completion(nil, PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: Send method cannot serialize request packet."));
        }
        return;
    }
    
    // Get a valid session
    WCSession * session = self.validSession;
    if (!session) {
        // On iOS, switch to debug build and check the log for the reason of unavailability.
        // On watchOS, the session is typically not activated
        PowerAuthLog(@"PA2WCSessionManager: WCSession is currently not available for messaging.");
        if (completion) {
            completion(nil, PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: WCSession is currently not available for messaging."));
        }
        return;
    }
    BOOL sessionIsReachable = session.reachable;
    if (withResponse) {
        //
        // Send with response
        //
        if (sessionIsReachable) {
            [session sendMessageData:requestData replyHandler:^(NSData * replyMessageData) {
                //
                BOOL failure;
                PA2WCSessionPacket * responsePacket = _DeserializePacket(replyMessageData, responseClass, &failure);
                NSError * responseError = responsePacket.error;
                if (!responsePacket) {
                    responseError = PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: Received response is in unknown data format.");
                }
                if (responseError) {
                    responsePacket = nil;
                }
                completion(responsePacket, responseError);
                //
            } errorHandler:^(NSError * error) {
                // Error from WCSession
                completion(nil, error);
                //
            }];
        } else {
            // Not reachable
            completion(nil, PA2MakeError(PowerAuthErrorCode_WatchConnectivity, @"PA2WCSessionManager: The counterpart device is not reachable."));
            return;
        }
    } else {
        //
        // send without response
        //
        if (sessionIsReachable) {
            [session sendMessageData:requestData replyHandler:nil errorHandler:^(NSError * _Nonnull error) {
                if ([error.domain isEqualToString:WCErrorDomain]) {
                    NSInteger ec = error.code;
                    if (ec == WCErrorCodeSessionNotSupported ||
                        ec == WCErrorCodeSessionNotActivated ||
                        ec == WCErrorCodeDeviceNotPaired ||
                        ec == WCErrorCodeWatchAppNotInstalled) {
                        PowerAuthLog(@"PA2WCSessionManager: Message for target '%@' failed to deliver. Error: %@", request.target, error);
                        return;
                    }
                }
                PowerAuthLog(@"PA2WCSessionManager: Message for target '%@' failed to deliver, but we'll try transferUserInfo. Error: %@", request.target, error);
                [session transferUserInfo: @{ PA2WCSessionPacket_USER_INFO_KEY : requestData }];
            }];
        } else {
            // The counterpart device is not reachable. We should use transferUserInfo instead...
            [session transferUserInfo: @{ PA2WCSessionPacket_USER_INFO_KEY : requestData }];
        }
    }
}

@end


// --------------------------------------------------------------------------------
#pragma mark - watchOS specific
// --------------------------------------------------------------------------------

#if defined(PA2_WATCH_SDK)

static WCSession * _PrepareSession(void)
{
    // On watchOS, we can always return defaultSession.
    return [WCSession defaultSession];
}

static WCSession * _ValidateSession(WCSession * session)
{
    if (session.activationState == WCSessionActivationStateActivated) {
        return session;
    }
    PowerAuthLog(@"PA2WCSessionManager: WCSession is not activated on this device.");
    return nil;
}

#endif // defined(PA2_WATCH_SDK)


// --------------------------------------------------------------------------------
#pragma mark - IOS specific
// --------------------------------------------------------------------------------

#if !defined(PA2_WATCH_SDK)

static WCSession * _PrepareSession(void)
{
    if ([WCSession isSupported]) {
        return [WCSession defaultSession];
    }
    return nil;
}

static WCSession * _ValidateSession(WCSession * session)
{
    // Check if session is paired and watch App is installed
    if (session.isPaired && session.isWatchAppInstalled) {
        if (session.activationState == WCSessionActivationStateActivated) {
            return session;
        }
    }
#ifdef DEBUG
    if (!session) {
        PowerAuthLog(@"PA2WCSessionManager: WCSession is not supported on this device.");
    } else {
        if (!session.isPaired) {
            PowerAuthLog(@"PA2WCSessionManager: Warning: This device is not paired with Apple Watch.");
        } else {
            PowerAuthLog(@"PA2WCSessionManager: Warning: Watch App is not installed on the currently paired and active Apple Watch.");
        }
    }
#endif // DEBUG
    return nil;
}

#endif // !defined(PA2_WATCH_SDK)

// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
