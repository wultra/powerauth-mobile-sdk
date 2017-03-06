/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#pragma once

/*
 The CryptoUtils.h private header contains all cryptographic related
 operations, required in the PA2 implementation.
 
 Note that all functionality provided by this header will
 be replaced with a similar cc7 implementation.
 */

#include "BNContext.h"
#include "AES.h"
#include "PRNG.h"
#include "ECC.h"
#include "Digest.h"
