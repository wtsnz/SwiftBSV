//
//  BigInt+Extension.swift
//  WalletKit
//
//  Created by yuzushioh on 2018/01/24.
//  Copyright © 2018 yuzushioh. All rights reserved.
//

import Foundation

extension BInt {
    internal init?(str: String, radix: Int) {
        self.init(0)
        let bint16 = BInt(16)
        
        var exp = BInt(1)
        
        str.reversed().forEach {
            guard let int = Int(String($0), radix: radix) else {
                return
            }
            let value = BInt(int)
            self += (value * exp)
            exp *= bint16
        }
    }
}

//extension BInt: Codable {
//    private enum CodingKeys: String, CodingKey {
//        case bigInt
//    }
//    
//    public init(from decoder: Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self)
//        let string = try container.decode(String.self, forKey: .bigInt)
//        self = Wei(number: string, withBase: 10)!
//    }
//    
//    public func encode(to encoder: Encoder) throws {
//        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(asString(withBase: 10), forKey: .bigInt)
//    }
//}

extension BInt {

    // These extensions are based upon the https://github.com/moneybutton/bsv lib and how it uses the BN.js class

    /// Returns the BInt's value as a hex string
    public func toHexString() -> String
    {
        // The asString method drops leading 0's which we don't want
        // This just adds it back in.
        // 208 -> 0208

        var hexString = asString(radix: 16)

        if hexString.count % 2 != 0 {
            hexString = "0" + hexString
        }

        return hexString
    }

    /// Returns a hex buffer of the BInt
    func toBuffer() -> Data {
        let hexString = toHexString()
        let data = Data(hex: hexString)
        return data
    }

    /// Return the buffer suitable for use in Script
    func toScriptNumBuffer() -> Data {
        return toSm(endian: "little")
    }

    /// Instantiate the BInt from a Script number buffer
    init(fromScriptNumBuffer buffer: Data) {
        self.init(fromSm: buffer, endian: "little")
    }

    /// Create from a signed magnitude buffer.
    /// Most significant bit represents sign (0 = positive, 1 = negative).
    init(fromSm buffer: Data, endian: String = "big") {
        var buffer = buffer

        if endian == "little" {
            buffer.reverse()
        }

        if buffer.count == 0 {
            self.init()
        } else {

            if buffer[0] & 0x80 != 0 {
                buffer[0] = buffer[0] & 0x7f
                let hex = buffer.hex
                self.init(str: hex, radix: 16)!
                self.negate()
            } else {
                let hex = buffer.hex
                self.init(str: hex, radix: 16)!
            }
        }
    }

    /// Returns a signed magnitude buffer.
    /// Most significant bit represents sign (0 = positive, 1 = negative).
    func toSm(endian: String = "big") -> Data {

        var buffer = Data()

        var copy = self

        if copy < 0 {
            copy.negate()
            buffer = copy.toBuffer()

            if ((buffer[0] & 0x80) != 0) {
                var newBuffer = Data()
                newBuffer += 0x80
                newBuffer += buffer
                buffer = newBuffer
            } else {
                buffer[0] = buffer[0] | 0x80
            }
        } else {
            buffer = toBuffer()

            if ((buffer[0] & 0x80) != 0) {
                var newBuffer = Data()
                newBuffer += 0x80
                newBuffer += buffer
                buffer = newBuffer
            }
        }

//        if ((buffer.count == 1) & (buffer[0] == 0)) != 0 {
//            buffer = Data()
//        }

        if endian == "little" {
            buffer.reverse()
        }

        return buffer
    }

    ///    Returns BInt's value as an integer. Conversion only works when self has only one limb
    /// that's within the range of the type "Int".
    func asInt32() -> Int32?
    {
        if self.limbs.count != 1 { return nil }

        let number = self.limbs[0]

        if number <= Limb(Int32.max)
        {
            return self.sign ? -Int32(number) : Int32(number)
        }

        if number == (Limb(Int32.max) + 1) && self.sign
        {
            // This is a special case where self == Int32.min
            return Int32.min
        }

        return nil
    }

}

extension BInt {
    var data: Data {
        let count = limbs.count
        var data = Data(count: count * 8)
        data.withUnsafeMutableBytes { (pointer) -> Void in
            guard var p = pointer.bindMemory(to: UInt8.self).baseAddress else { return }
            for i in (0..<count).reversed() {
                for j in (0..<8).reversed() {
                    p.pointee = UInt8((limbs[i] >> UInt64(j * 8)) & 0xff)
                    p += 1
                }
            }
        }
        
        return data
    }
    
    init(data: Data) {
        let n = data.count
        guard n > 0 else {
            self.init(0)
            return
        }
        
        let m = (n + 7) / 8
        var limbs = Limbs(repeating: 0, count: m)
        data.withUnsafeBytes { (ptr) -> Void in
            guard var p = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            let r = n % 8
            let k = r == 0 ? 8 : r
            for j in (0..<k).reversed() {
                limbs[m - 1] += UInt64(p.pointee) << UInt64(j * 8)
                p += 1
            }
            guard m > 1 else { return }
            for i in (0..<(m - 1)).reversed() {
                for j in (0..<8).reversed() {
                    limbs[i] += UInt64(p.pointee) << UInt64(j * 8)
                    p += 1
                }
            }
        }
        
        self.init(limbs: limbs)
    }
}
