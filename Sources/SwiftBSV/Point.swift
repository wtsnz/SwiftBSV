//
//  Point.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

// TODO: Do we really need the BInt class?
// We don't do any math on them in Swift, so why add the complication? We can simply store the
// backing Data in the point, and defer to the secp256k1 lib to do the maths...

public struct Point {

    // From the secp256k1 curve definition
    // https://github.com/indutny/elliptic/blob/master/lib/elliptic/curves.js#L176
//    static let P = BInt(str: "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", radix: 16)!

    static let N = BInt(str: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", radix: 16)!

    public let x: BInt
    public let y: BInt

    public init(x: BInt, y: BInt) {
        self.x = x
        self.y = y
    }

    /// Init Point from a DER buffer
    /// - Parameter buffer: the DER formatted buffer
    public init?(buffer: Data) {
        let uncompressedPublicKeyData = Crypto.serializePublicKey(from: buffer, compressed: false)

        guard uncompressedPublicKeyData.count == 65 else {
            fatalError("Point: invalid uncompressedPublicKeyData length")
        }

        let x = uncompressedPublicKeyData.dropFirst().prefix(32)
        let y = uncompressedPublicKeyData.dropFirst().suffix(32)

        self.x = BInt(data: x)
        self.y = BInt(data: y)
    }

    func serialize(compressed: Bool = true) -> Data {
        return Crypto.serializePublicKey(from: x.data, compressed: compressed)
    }

}
