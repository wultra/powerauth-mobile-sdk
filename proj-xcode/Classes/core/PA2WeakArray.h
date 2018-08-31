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

#import <Foundation/Foundation.h>

/**
 The PA2WeakArray implements simple mutable array for storing weak object references.
 The array shrinks its size when some stored weak reference become nil.
 */
@interface PA2WeakArray<ObjectType>: NSObject

/**
 Initializes empty array.
 */
- (instancetype _Nonnull) init;
/**
 Initializes empty array and reserves internal storage capacity to |capacity| items.
 */
- (instancetype _Nonnull) initWithCapacity:(NSUInteger)capacity;
/**
 Initializes array with content form |objects| array.
 */
- (instancetype _Nonnull) initWithObjects:(nonnull NSArray<ObjectType> *)objects;

/**
 Returns number of weak objects stored in the array. The getter doesn't filter nil objects,
 so the returned value may count also with already invalid objects.
 */
@property (nonatomic, readonly) NSUInteger count;

/**
 Adds weak reference to |object| to the array.
 */
- (void) addWeakObject:(nonnull ObjectType)object;
/**
 Removes weak reference to |object| frim the array. When object is no longer in the array,
 then does nothing.
 */
- (void) removeWeakObject:(nonnull ObjectType)object;
/**
 At first, removes all nil references from underlying array and then enumerates over all
 still valid objects.
 */
- (void) enumerateWeakObjectsUsingBlock:(void (NS_NOESCAPE ^_Nonnull)(ObjectType _Nonnull item, BOOL * _Nonnull stop))block;
/**
 At first, removes all nil references from underlying array and then calls block for each still valid object.
 The enumeration stops when block returns YES and the last enumerated object is returned.
 */
- (nullable ObjectType) findObjectUsingBlock:(BOOL (NS_NOESCAPE ^_Nonnull)(ObjectType _Nonnull item))block;
/**
 At first, removes all nil references from underlying array and then returns all still valid objects in
 strong referenced array.
 */
- (nonnull NSArray<ObjectType> *) allNonnullObjects;

@end
