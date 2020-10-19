//
//  Base58Check.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

public struct Base58Check {

    public static func encode(_ bytes: Data) -> String {
        let checksum = bytes.doubleSHA256.prefix(4)
        return Base58.encode(bytes + checksum)
    }

    public static func decode(_ string: String) -> Data? {

        guard let buffer = Base58.decode(string) else {
            return nil
        }

        guard buffer.count > 4 else {
            // Input buffer is too small
            return nil
        }

        let data = buffer.prefix(buffer.count - 4)
        let checksum = buffer.suffix(4)

        let hash = data.doubleSHA256
        let hash4 = hash.prefix(4)

        guard hash4 == checksum else {
            // Invalid checksum
            return nil
        }

        return data
    }
}
