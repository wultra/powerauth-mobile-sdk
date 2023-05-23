/*
 * Copyright (c) 2023, Wultra s.r.o. (www.wultra.com).
 *
 * All rights reserved. This source code can be used only for purposes specified
 * by the given license contract signed by the rightful deputy of Wultra s.r.o.
 * This source code can be used only by the owner of the license.
 *
 * Any disputes arising in respect of this agreement (license) shall be brought
 * before the Municipal Court of Prague.
 */

#import "PowerAuthTestServerConfig.h"

@interface RestHelper : NSObject
/**
 Contains internal NSURLSession object.
 */
@property (nonatomic, strong, readonly) NSURLSession * session;

/**
 Initializes an instance of RestHelper object with |bundle| containing the endoints templates.
 The |url| defines endpoint, where the server listens for messages.
 */
- (id) initWithBundle:(NSBundle*)bundle
               config:(PowerAuthTestServerConfig*)config;

/**
 Apply server version and return the version enumeration.
 */
- (PowerAuthTestServerVersion) applyServerVersion:(NSString*)version;

/**
 Execute request with parameters.
 */
- (id) request:(NSString*)requestName params:(NSArray*)params;

@end
