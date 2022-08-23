//
// Copyright 2022 Wultra s.r.o.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.
//

import SwiftUI

import PowerAuth2
import PowerAuthCore

struct ContentView: View {
    var body: some View {
        Text("Executing PowerAuth integration tests.")
            .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

/// This function is useful only for test whether our Objective-C API
/// is properly exposed to Swift. You can prototype any code you want
/// here to see, whether our API makes sense in Swift.
///
/// Please revert your changes in this file before you commit & push
/// the rest of your work into the repository.
fileprivate func dummyFunction() {
    let config = PowerAuthConfiguration()
    let sdk = PowerAuthSDK(configuration: config)!
    _ = sdk.hasBiometryFactor()
}
