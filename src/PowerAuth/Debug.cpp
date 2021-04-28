/*
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

#include <PowerAuth/Debug.h>

using namespace cc7;

namespace io
{
namespace getlime
{
namespace powerAuth
{

#if defined(DEBUG)
	// Following string is useful for debug build detection during the library deployment.
	// Check out our 'android-validate-build.sh' script for details.
	const char * gFooDEBUG = "ThisIsDebugBuild_PA";
#endif

	bool HasDebugFeaturesTurnedOn()
	{
		// Get features status from CC7 library
		bool debug_features = cc7::debug::HasDebugFeaturesTurnedOn();
		// and combine this with features in this library
#if defined(DEBUG)
		debug_features |= true;
#endif
		return debug_features;
	}
	
} // io::getlime::powerAuth
} // io::getlime
} // io

