//
//  Signature.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-26.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

struct Signature {

    var r: Data
    var s: Data

    var nHashType: SighashType?
    var recovery: Int?
    var isCompressed: Bool?

    // MARK: - Initializers

    init(r: Data, s: Data, nHashType: SighashType? = nil, recovery: Int? = nil, compressed: Bool? = nil) {
        self.r = r
        self.s = s
        self.nHashType = nHashType
        self.recovery = recovery
        self.isCompressed = compressed
    }

    init?(fromRsBuffer buffer: Data) {
        guard buffer.count == 64 else {
            return nil
        }

        self.r = buffer[0..<32]
        self.s = buffer[32..<64]
    }

    init?(txFormatBuffer buffer: Data) {
        let nHashType = buffer[buffer.count - 1]
        let derBuffer = Data(buffer.prefix(buffer.count - 1))

        guard let sig = Signature.parseDER(buffer: derBuffer) else {
            return nil
        }

        self.nHashType = BSVSighashType(rawValue: nHashType)
        if self.nHashType == nil {
            self.nHashType = BTCSighashType(rawValue: nHashType)
        }

        self.r = sig.r
        self.s = sig.s
    }

    /// The format used in the Bitcoin Signed Message
    init?(fromCompact buffer: Data) {
        guard buffer.count == 1 + 32 + 32 else {
            return nil
        }

        var compressed = true
        var recoveryId = Int(Int(buffer[0]) - 27 - 4)
        if recoveryId < 0 {
            compressed = false
            recoveryId = recoveryId + 4
        }

        let rsBuffer = Data(buffer[1..<buffer.count])

        self.init(fromRsBuffer: rsBuffer)

        self.isCompressed = compressed
        self.recovery = recoveryId
    }

    // MARK: - 'To' conversions

    func toBuffer() -> Data {
        if nHashType != nil {
            return toTxFormat()
        } else if recovery != nil {
            return toCompact()
        }
        return toDer()
    }

    func toCompact(recovery: Int? = nil, compressed: Bool? = nil) -> Data {

        guard let recovery: Int = {
            if let recovery = recovery {
                return recovery
            } else if let selfRecovery = self.recovery {
                return selfRecovery
            } else {
                return nil
            }
        }() else {
            fatalError("Missing recovery value")
        }

        let compressed: Bool = {
            if let compressed = compressed {
                return compressed
            } else if let selfIsCompressed = self.isCompressed {
                return selfIsCompressed
            } else {
                return true
            }
        }()

        guard (0...3).contains(recovery) else {
            return Data() // Invalid recovery
        }

        var val = recovery + 27 + 4
        if !compressed {
            val = val - 4
        }

        var buffer = Data()
        buffer += UInt8(val)
        buffer += r
        buffer += s
        return buffer
    }

    func toDer() -> Data {
        let r = self.r
        let s = self.s
        let rneg = r.bytes[0] & 0x80
        let sneg = s.bytes[0] & 0x80

        var rbuf = Data()
        if rneg == 1 {
            rbuf += UInt8(0)
            rbuf += r
        } else {
            rbuf += r
        }

        var sbuf = Data()
        if sneg == 1 {
            sbuf += UInt8(0)
            sbuf += s
        } else {
            sbuf += s
        }

        let header = UInt8(0x30)
        let length = UInt8(2 + r.count + 2 + s.count)
        let rheader = UInt8(2)
        let sheader = UInt8(2)

        var data = Data()
        data += header
        data += length
        data += rheader
        data += UInt8(rbuf.count)
        data += rbuf
        data += sheader
        data += UInt8(sbuf.count)
        data += sbuf

        return data
    }

    func toTxFormat() -> Data {
        let derBuffer = self.toDer()
        let nHashTypeBuf: Data = {
            var buf = Data()
            if let nHashType = self.nHashType {
                buf += nHashType.rawValue
            } else {
                buf += UInt8(0)
            }
            return buf
        }()

        var data = Data()
        data += derBuffer
        data += nHashTypeBuf

        return data
    }

    // MARK: -

    static func parseDER(buffer: Data, strict: Bool = true) -> (r: Data, s: Data)? {
        let header = buffer[0]

        guard header == 0x30 else {
            return nil
        }

        var length = Int(buffer[1])
        let bufferLength = buffer.suffix(from: 2).count
        if (strict && length != bufferLength) {
            // Length byte should length of what follows
            return nil
        } else {
            length = length < bufferLength ? length : bufferLength
        }


        // Parse the R value

        var offset = 2
        var count = 1

        let rHeader = buffer[2 + 0]
        guard rHeader == 0x02 else {
            fatalError("Signature: Invalid r header")
        }

        let rLength = Int(buffer[2 + 1])
        offset = 2 + 2
        count = rLength
        let rBuffer = buffer[offset..<(offset + count)]

        let r = BInt(data: rBuffer)
        let rneg = buffer[2 + 1 + 1] == 0x00

        // Parse the S value

        offset = 2 + 2 + rLength
        count = 1
        let sHeader = buffer[offset]
        guard sHeader == 0x02 else {
            fatalError("Signature: Invalid S header")
        }

        offset = 2 + 2 + rLength + 1
        count = 1
        let sLength = Int(buffer[offset])
        offset = 2 + 2 + rLength + 2
        count = sLength

        let sBuffer = buffer[offset..<(offset+count)]

        let s = BInt(data: sBuffer)
        offset = 2 + 2 + rLength + 2 + 2
        let sneg = buffer[offset] == 0x00

        // Validate length

        let sumLength = 2 + 2 + rLength + 2 + sLength
        guard sumLength - 2 == length else {
            fatalError("Length of signature incorrect")
        }

        return (
            r: rBuffer,
            s: sBuffer
        )

    }

}
