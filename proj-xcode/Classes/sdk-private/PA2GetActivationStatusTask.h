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

#import "PA2OperationTask.h"

@class PA2ActivationStatus;
@class PA2GetActivationStatusChildTask;
@class PA2HttpClient;
@class PA2Session;

/**
 The `PA2GetActivationStatusTask` class implements getting activation status from the server
 and the protocol migration. The migration is started automatically, depending on the
 local and server's state of the activation.
 */
@interface PA2GetActivationStatusTask : NSObject<PA2OperationTask>

/**
 Initializes the object.

 @param httpClient HTTP client for communicating with the server
 @param deviceRelatedKey key for unlocking possession factor
 @param session PA2Session object providing low level protocol tasks
 @param sessionChange closure called, when the state of PA2Session needs to be serialized.
 @param completion closure called at the end of operation
 @return initialized object
 */
- (id) initWithHttpClient:(PA2HttpClient*)httpClient
		 deviceRelatedKey:(NSData*)deviceRelatedKey
				  session:(PA2Session*)session
			sessionChange:(void(^)(PA2Session*))sessionChange
			   completion:(void(^)(PA2GetActivationStatusTask*))completion;

/**
 Set to YES after task is constructed, to disable protocol migration
 */
@property (nonatomic, assign) BOOL disableMigration;

/**
 Adds new child task to this object.

 @param task child task associated with this object
 @return YES if operation succeeded and NO if this task is being completed.
 */
- (BOOL) addChildTask:(PA2GetActivationStatusChildTask*)task;

/**
 Cancles previously added child task..

 @param task child task to be cancelled
 */
- (void) cancelChildTask:(PA2GetActivationStatusChildTask*)task;


/**
 Executes this task.
 */
- (void) execute;

@end



/**
 The `PA2GetActivationStatusChildTask` is task returned to the application when activation
 status is requested.
 */
@interface PA2GetActivationStatusChildTask : NSObject<PA2OperationTask>

/**
 Initializes child task with parent task, completion queue & completion closure.

 @param task Parent taks, which will manage this object.
 @param completionQueue queue where
 @param callback closure called when the parent task finishes its execution.
 @return instance of child task.
 */
- (instancetype) initWithCompletionQueue:(dispatch_queue_t)completionQueue
							  completion:(void(^)(PA2ActivationStatus *, NSDictionary *, NSError *))callback;

@end
