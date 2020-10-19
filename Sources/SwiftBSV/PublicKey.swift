//
//  PublicKey.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

struct PublicKey {

    /// The Point of the public key on the curve.
    public let point: Point

    let isCompressed: Bool

    /// Create a PublicKey from a DER hex string.
    public init?(hex: String) {
        self.init(fromDer: Data(hex: hex))
    }

    /// Create a PublicKey from a DER formatted buffer.
    ///
    /// In order to mimic the non-strict style of OpenSSL, set strict = false. For
    /// information and what prefixes 0x06 and 0x07 mean, in addition to the normal
    /// compressed and uncompressed public keys, see the message by Peter Wuille
    /// where he discovered these "hybrid pubKeys" on the mailing list:
    /// http://sourceforge.net/p/bitcoin/mailman/message/29416133/
    ///
    /// - Parameters:
    ///   - buffer: Buffer containing the DER formatted PublicKey. This can be in the compressed, or uncompressed format.
    ///   - isStrict: See above discussion
    public init?(fromDer buffer: Data, isStrict strict: Bool = true) {
        /// The buffer is uncompressed, and contains the X and Y coordinate of the Point
        if buffer[0] == 0x04 || (!strict && (buffer[0] == 0x06 || buffer[0] == 0x07)) {

            if buffer.count != 65 {
                return nil
            }

            let xBuffer = buffer[1..<33]
            let yBuffer = buffer[33..<65]

            let x = BInt(data: xBuffer)
            let y = BInt(data: yBuffer)

            point = Point(x: x, y: y)
            isCompressed = false

        }
        // The buffer is compressed, and contains only the X coordinate of the Point
        else if buffer[0] == 0x03 || buffer[0] == 0x02 {

            guard let point = Point(buffer: buffer) else {
                return nil
            }

            self.point = point
            isCompressed = true

        } else {
            return nil
        }
    }

    /// Encode the PublicKey into DER data
    /// - Returns: DER data buffer
    public func toDer() -> Data {
        let xBuffer = point.x.data
        let yBuffer = point.y.data

        if isCompressed {
            let isEven = yBuffer[yBuffer.count - 1] % 2 == 0
            var data = Data()
            // Add the prefix
            data += isEven ? UInt8(0x02) : UInt8(0x03)
            data += xBuffer
            return data
        } else {
            var data = Data()
            data += UInt8(0x04)
            data += xBuffer
            data += yBuffer
            return data
        }
    }

}

extension PublicKey: CustomStringConvertible {
    public var description: String {
        return toDer().hex
    }
}
