//
//  Point.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

struct Point {

    // From the secp256k1 curve definition
    // https://github.com/indutny/elliptic/blob/master/lib/elliptic/curves.js#L176
    static let P = BInt(str: "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", radix: 16)!
    static let N = BInt(str: "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", radix: 16)!

    public let x: BInt
    public let y: BInt

    public init(x: BInt, y: BInt) {
        self.x = x
        self.y = y
    }

    static func calculateYfromX(x: BInt, isOdd: Bool) -> BInt? {
        let p = Point.P
        let y_sq = (BIntMath.mod_exp(x, BInt(3), p) + BInt(7)) % p
        let y = BIntMath.mod_exp(y_sq, (p + BInt(1)) / BInt(4), p)

        if BIntMath.mod_exp(y, BInt(2), p) != y_sq {
            return nil
        }

        return y
    }

}
