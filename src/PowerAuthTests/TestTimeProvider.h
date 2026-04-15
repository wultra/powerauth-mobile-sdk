/*
 * Copyright 2025 Wultra s.r.o.
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

#include <PowerAuth/TimeService.h>
#include <math.h>

namespace powerAuthTests {

class TestTimeProvider : public powerAuth::ITimeProvider
{
public:
    TestTimeProvider() {
        setTime(cc7::GetCurrentTime());
    }
    
    powerAuth::TimeInterval getCurrentTime() const noexcept override
    {
        if (validInterval) {
            return testTime;
        }
        return 0.001 * timestamp;
    }
    
    powerAuth::Timestamp getCurrentTimeMillis() const noexcept override
    {
        if (validInterval) {
            return 1000 * testTime;
        }
        return timestamp;
    }
    
    void setTimestamp(powerAuth::Timestamp time)
    {
        validInterval = false;
        timestamp = time;
    }
    
    void setTime(powerAuth::TimeInterval time)
    {
        validInterval = true;
        testTime = time;
    }
    
    void sleepThread(powerAuth::TimeInterval interval)
    {
        // add a random value to make the time advance real.
        setTime(getCurrentTime() + ((double)arc4random_uniform(1000)) * 0.0001 + interval);
    }
    
private:
    bool validInterval = false;
    powerAuth::TimeInterval testTime;
    powerAuth::Timestamp timestamp;
};

static inline bool DoubleIsEqual(double a, double b, double epsilon)
{
    return fabs(a - b) < epsilon;
}

const double T_epsilon = 1e-5;

static inline bool TimeIntervalIsEqual(powerAuth::TimeInterval a, powerAuth::TimeInterval b)
{
    return DoubleIsEqual(a, b, T_epsilon);   // 10us
}

static inline bool TimeIntervalInRange(powerAuth::TimeInterval t, double min, double max)
{
    return (t > min - T_epsilon) && (t < max + T_epsilon);
}


} // namespace powerAuthTests
