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

#import "PA2WeakArray.h"

@interface PA2WeakObject : NSObject
@property (nonatomic, nullable, weak, readonly) id instance;
- (nonnull id) initWithInstance:(nonnull id)instance;
- (BOOL) instanceIsEqualToObject:(nonnull id)object;
@end

@implementation PA2WeakObject

- (id) initWithInstance:(id)instance
{
	self = [super init];
	if (self) {
		_instance = instance;
	}
	return self;
}

- (BOOL) instanceIsEqualToObject:(id)object
{
	id strongInstance = _instance;
	if (strongInstance && object) {
		return strongInstance == object;
	}
	return NO;
}

@end


@implementation PA2WeakArray
{
	NSMutableArray * _array;
}

- (instancetype) init
{
	self = [super init];
	if (self) {
		_array = [NSMutableArray array];
	}
	return self;
}

- (instancetype) initWithCapacity:(NSUInteger)capacity
{
	self = [super init];
	if (self) {
		_array = [NSMutableArray arrayWithCapacity:capacity];
	}
	return self;
}

- (instancetype) initWithObjects:(nonnull NSArray *)objects
{
	self = [super init];
	if (self) {
		_array = [NSMutableArray arrayWithCapacity:objects.count];
		[objects enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
			[_array addObject:[[PA2WeakObject alloc] initWithInstance:obj]];
		}];
	}
	return self;
}

#pragma mark - Manipulation with array

- (void) addWeakObject:(nonnull id)object
{
	[_array addObject:[[PA2WeakObject alloc] initWithInstance:object]];
}

- (void) removeWeakObject:(nonnull id)object
{
	[_array enumerateObjectsUsingBlock:^(PA2WeakObject * weakObj, NSUInteger idx, BOOL * stop) {
		if ([weakObj instanceIsEqualToObject:object]) {
			[_array removeObjectAtIndex:idx];
			*stop = YES;
		}
	}];
}

- (void) enumerateWeakObjectsUsingBlock:(void (^_Nonnull)(id item, BOOL * stop))block
{
	if (block) {
		[[self allNonnullObjects] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
			block(obj, stop);
		}];
	}
}

#pragma mark - Getting strong reference

- (NSUInteger) count
{
	return [_array count];
}

- (NSArray*) allNonnullObjects
{
	NSMutableArray * strongArray = [NSMutableArray arrayWithCapacity:_array.count];
	[[_array copy] enumerateObjectsUsingBlock:^(PA2WeakObject * weakObj, NSUInteger idx, BOOL * stop) {
		id strongInstance = weakObj.instance;
		if (strongInstance) {
			[strongArray addObject:strongInstance];
		} else {
			[_array removeObjectAtIndex:idx];
		}
	}];
	return strongArray;
}

- (id) findObjectUsingBlock:(BOOL (^)(id item))block
{
	if (block) {
		for (id strongInstance in [self allNonnullObjects]) {
			if (block(strongInstance)) {
				return strongInstance;
			}
		}
	}
	return nil;
}

@end
