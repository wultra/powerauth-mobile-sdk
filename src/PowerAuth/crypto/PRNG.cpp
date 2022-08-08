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

#include "PRNG.h"
#include <openssl/rand.h>

#if defined(CC7_APPLE) || defined(CC7_ANDROID)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
    
    static bool GetBytesFromSystemGenerator(void * out_buffer, size_t nbytes);
    
    // MARK: - Public functions -

    cc7::ByteArray GetRandomData(size_t size, bool reject_sequence_of_zeros)
    {
        cc7::ByteArray data(size, 0);
        cc7::ByteArray zeros;
        size_t attempts = 16;
        while (size > 0) {
            int rc = RAND_bytes(data.data(), (int)size);
            if (rc != 1 || attempts == 0) {
                CC7_ASSERT(false, "Random data generation failed!");
                return cc7::ByteArray();
            }
            if (!reject_sequence_of_zeros) {
                break;
            }
            if (zeros.size() != size) {
                zeros.assign(size, 0);
            }
            if (data != zeros) {
                break;
            }
            --attempts;
        }
        return data;
    }
    
    
    cc7::ByteArray GetUniqueRandomData(size_t size, const std::vector<const cc7::ByteRange> & reject_byte_sequences)
    {
        cc7::ByteArray data(size, 0);
        size_t attempts = 16;
        while (size > 0) {
            int rc = RAND_bytes(data.data(), (int)size);
            if (rc != 1 || attempts == 0) {
                CC7_ASSERT(false, "Random data generation failed!");
                return cc7::ByteArray();
            }
            bool unique = true;
            for (auto && other_data : reject_byte_sequences) {
                if (data.byteRange() == other_data) {
                    unique = false;
                    break;
                }
            }
            if (unique) {
                break;
            }
            --attempts;
        }
        return data;
    }
    

    void ReseedPRNG()
    {
        static bool s_initial_seed = true;
        size_t nbytes;
        if (s_initial_seed) {
            // This is an initial seed. The recommended size for OpenSSL's PRNG is 1024 bytes
            s_initial_seed = false;
            nbytes = 1024;
        } else {
            // All subsequent re-seeds may be shorter.
            unsigned char count = 16;
            RAND_bytes(&count, sizeof(unsigned char));
            if (count < 16) {
                count = 16;
            } else if (count > 64) {
                count = 64;
            }
            nbytes = count;
        }
        
        uint8_t * buffer = new uint8_t[nbytes];
        if (CC7_CHECK(GetBytesFromSystemGenerator(buffer, nbytes), "Unable to seed PRNG")) {
            RAND_seed(buffer, (int)nbytes);
        }
        delete []buffer;
    }
    
    // MARK: - Platform specific implementations -
    
#if defined(CC7_APPLE) || defined(CC7_ANDROID)
    
    static bool GetBytesFromSystemGenerator(void * out_buffer, size_t nbytes)
    {
        int fd = open("/dev/urandom", O_RDONLY);
        bool result = false;
        if (fd >= 0 && out_buffer != nullptr) {
            ssize_t readed = read(fd, out_buffer, nbytes);
            result = readed == nbytes;
            close(fd);
        }
        return result;
    }
    
#else
#error Unsupported platform
#endif
    
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
