/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PowerAuthTestServerModel.h"

@interface PowerAuthTestServerAPI : NSObject

- (id) initWithTestServerURL:(NSURL*)testServerUrl
			 applicationName:(NSString*)applicationName
		  applicationVersion:(NSString*)applicationVersion;

- (BOOL) validateConnection;

// Soap requests

- (NSArray<PATSApplication*>*) getApplicationList;
- (PATSApplicationDetail*) getApplicationDetail:(NSString*)applicationId;
- (PATSApplicationVersion*) createApplicationVersion:(NSString*)applicationId versionName:(NSString*)versionName;

// Environment
@property (nonatomic, readonly, strong) NSString * applicationNameString;
@property (nonatomic, readonly, strong) NSString * applicationVersionString;

@property (nonatomic, readonly, strong) PATSApplicationDetail  * appDetail;
@property (nonatomic, readonly, strong) PATSApplicationVersion * appVersion;

@end
