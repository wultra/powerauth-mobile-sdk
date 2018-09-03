# -------------------------------------------------------------------------
# Copyright 2016-2017 Wultra s.r.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -------------------------------------------------------------------------

APP_STL := c++_static

# WARNING:
# If you change supported ABIs then make sure that you have pre-compiled
# appropriate OpenSSL library. Check {GIT_ROOT}/cc7/openssl/openssl-version.sh

APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
