#!/usr/bin/env swift
//
// Copyright 2023 Wultra s.r.o.
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
// See the License for the specific language governing permissions and
// limitations under the License.
//
import Foundation

func help(_ result: Int32 = 0) -> Never {
    print("\nThis helper script parse simplified configuration introduced in PowerAuth Server 1.5")
    print("into legacy parameters that can be used to configure PowerAuth mobile SDK older than 1.8.0\n")
    print("Usage : \(CommandLine.arguments[0]) base64-encoded-configuration\n")
    exit(result)
}

class DataReader {
    let data: Data
    var ptr = 0;
    var isError = false
    var remaining: Int { return data.count - ptr }
    init(data: Data) {
        self.data = data
    }
    func readCount() -> Int {
        let b0 = readByte()
        switch b0 & 0xC0 {
        case 0x00, 0x40:
            // just one byte
            return Int(b0)
        case 0xC0:
            // three more bytes
            return Int(
                (Int(b0 & 0x3F)  << 24) |
                (Int(readByte()) << 16) |
                (Int(readByte()) << 8 ) |
                 Int(readByte())
            )
        default:
            // one more byte
            return Int(
                (Int(b0 & 0x3F) << 8) |
                 Int(readByte())
            )
        }
    }
    func readData() -> Data {
        let count = readCount()
        guard canRead(size: count) else { return Data() }
        let result = data.subdata(in: ptr..<ptr + count)
        ptr += count
        return result
    }
    func readByte() -> UInt8 {
        guard canRead(size: 1) else { return 0 }
        let result = data[ptr]
        ptr += 1
        return result
    }
    func canRead(size: Int) -> Bool {
        guard !isError else { return false }
        let result = ptr + size <= data.count
        isError = !result
        return result
    }
}

func dumpLegacyConfig(config: String) -> Bool {
    
    let VERSION_1: UInt8 = 0x01
    let P256_KEY_ID: UInt8 = 0x01
    
    guard let configData = Data(base64Encoded: config) else {
        print("Input string is not Base64 encoded.")
        return false
    }
    let reader = DataReader(data: configData)
    let version = reader.readByte()
    guard version == VERSION_1 else {
        print("Invalid configuration version.")
        return false
    }
    let appKey = reader.readData()
    let appSecret = reader.readData()
    guard !appKey.isEmpty && !appSecret.isEmpty else {
        print("Invalid configuration format.")
        return false
    }

    var p256key = Data()
    var count = reader.readCount()
    while count > 0 && reader.isError == false {
        let keyId = reader.readByte()
        let keyData = reader.readData()
        if keyId == P256_KEY_ID {
            p256key = keyData
        }
        count -= 1
    }
    guard !p256key.isEmpty else {
        print("Missing P-256 public key in the configuration")
        return false
    }
    print("Legacy PowerAuth configuration:")
    print("   appKey                : \(appKey.base64EncodedString())")
    print("   appSecret             : \(appSecret.base64EncodedString())")
    print("   masterServerPublicKey : \(p256key.base64EncodedString())")
    return !reader.isError
}

let arguments = CommandLine.arguments
guard arguments.count > 1 else { help(1) }
for i in 1..<arguments.count {
    let param = arguments[i]
    switch param {
    case "-h", "--help":
        help()
    default:
        if dumpLegacyConfig(config: param) == false {
            exit(1)
        }
    }
}
