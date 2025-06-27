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

#include <cc7/ByteArray.h>

namespace powerAuth {

/// The `ActivationState` defines state of local activation. Be aware that this
/// enumeration is not identical with state of activation on the server. To get
/// the state on the server, look for `ActivationStatus::ServerState` enumeration.
enum class ActivationState
{
    /// There's no local activation.
    Empty,
    /// Device's public keys sent to server and awaiting the response
    /// from the server.
    KeyExchange,
    /// Activation is awaiting for confirmation with an authentication code.
    PendingConfirmation,
    /// Activation is confirmed, but awaits for commit on the server.
    PendingCommit,
    /// Activation is active and ready for operation.
    Active,
    /// Activation is blocked.
    Blocked,
    /// Activation is removed on the server.
    Removed,
    /// Activation is technically blocked, due to out-of-sync counters
    /// between client and the server.
    Deadlock,
};

class ActivationStatus
{
public:
    
    /// The `ServerState` defines all possible states of activation on the server.
    enum ServerState
    {
        Created         = 1,
        PendingCommit   = 2,
        Active          = 3,
        Blocked         = 4,
        Removed         = 5,
    };
    
    /// The `CounterState` defines state of local counter against the server counter.
    enum CounterState
    {
        /// The state is not determined yet.
        Counter_NA = 0,
        /// Counter is healthy, no additional action is required.
        Counter_OK,
        /// Counter was just updated, so the session's persistent
        /// data needs to be serialized.
        Counter_Updated,
        /// The PowerAuth symmetric signature should be calculated
        /// to prevent counter's de-synchronization.
        Counter_CalculateSignature,
        /// Counter is invalid and the activation is technically blocked.
        Counter_Invalid
    };

    // TODO: missing impl.
    
private:
};

CC7_SHARED_PTR(ActivationStatus)

} // namespace powerAuth
