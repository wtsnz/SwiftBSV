//
//  SighashType.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 1/7/19.
//  Copyright © 2019 Essentia. All rights reserved.
//

import Foundation

private let SIGHASH_ALL: UInt8 = 0x01 // 00000001
private let SIGHASH_NONE: UInt8 = 0x02 // 00000010
private let SIGHASH_SINGLE: UInt8 = 0x03 // 00000011
private let SIGHASH_FORK_ID: UInt8 = 0x40 // 01000000
private let SIGHASH_ANYONECANPAY: UInt8 = 0x80 // 10000000

private let SIGHASH_OUTPUT_MASK: UInt8 = 0x1f // 00011111

//public enum SighashBase: UInt8 {
//    case all = 1
//    case none = 2
//    case single = 3
//
//    var uint32: UInt32 {
//        return UInt32(rawValue)
//    }
//}
//
//public struct SighashTypeV2 {
//
//    let base: SighashBase
//    let anyoneCanPay: Bool
//    let hasForkId: Bool
//
//    var uint32: UInt32 {
//        var base = self.base.uint32
//
//        if anyoneCanPay {
//            base = base | 0x80
//        }
//
//        if hasForkId {
//            base = base | 0x40
//        }
//
//        return base
//    }
//
//    init(base: SighashBase, anyoneCanPay: Bool, hasForkId: Bool) {
//        self.base = base
//        self.anyoneCanPay = anyoneCanPay
//        self.hasForkId = hasForkId
//    }
//
//    static func from(_ uint: UInt32) -> SighashTypeV2? {
//        let anyoneCanPay = (uint & 0x80) == 0x80
//        let hasForkId = (uint & 0x40) == 0x40
//        let base: SighashBase = {
//            switch (uint & 0x1f) {
//            case 3:
//                return .single
//            case 2:
//                return .none
//            case 1:
//                return .all
//            default:
//                return .all
//            }
//        }()
//
//        return SighashTypeV2(
//            base: base,
//            anyoneCanPay: anyoneCanPay,
//            hasForkId: hasForkId
//        )
//    }
//
//
//}

public struct SighashType {
    fileprivate let uint8: UInt8

    init(int: Int) {
        self.init(uint32: UInt32(truncatingIfNeeded: int))
    }

    init(_ uint8: UInt8) {
        self.uint8 = uint8
    }

    init(uint32 uint: UInt32) {
        let anyoneCanPay = (uint & 0x80) == 0x80
        let hasForkId = (uint & 0x40) == 0x40
        let base: UInt8 = {
            switch (uint & 0x1f) {
            case 3:
                return 3
            case 2:
                return 2
            case 1:
                return 1
            default:
                return 1
            }
        }()

        var uint8 = base

        if anyoneCanPay {
            uint8 = SIGHASH_ANYONECANPAY + uint8
        }

        if hasForkId {
            uint8 = SIGHASH_FORK_ID + uint8
        }

        self.uint8 = uint8
    }

    public var rawValue: UInt8 {
        return uint8
    }

    public var uint32: UInt32 {
        return UInt32(rawValue)
    }

    private var outputType: UInt8 {
        return self.uint8 & SIGHASH_OUTPUT_MASK
    }
    public var isAll: Bool {
        return outputType == SIGHASH_ALL
    }
    public var isSingle: Bool {
        return outputType == SIGHASH_SINGLE
    }
    public var isNone: Bool {
        return outputType == SIGHASH_NONE
    }

    public var hasForkId: Bool {
        return (self.uint8 & SIGHASH_FORK_ID) != 0
    }
    public var isAnyoneCanPay: Bool {
        return (self.uint8 & SIGHASH_ANYONECANPAY) != 0
    }

    public struct BSV {
        public static let ALL: SighashType = SighashType(SIGHASH_FORK_ID + SIGHASH_ALL) // 01000001
        public static let NONE: SighashType = SighashType(SIGHASH_FORK_ID + SIGHASH_NONE) // 01000010
        public static let SINGLE: SighashType = SighashType(SIGHASH_FORK_ID + SIGHASH_SINGLE) // 01000011
        public static let ALL_ANYONECANPAY: SighashType = SighashType(SIGHASH_FORK_ID + SIGHASH_ALL + SIGHASH_ANYONECANPAY) // 11000001
        public static let NONE_ANYONECANPAY: SighashType = SighashType(SIGHASH_FORK_ID + SIGHASH_NONE + SIGHASH_ANYONECANPAY) // 11000010
        public static let SINGLE_ANYONECANPAY: SighashType = SighashType(SIGHASH_FORK_ID + SIGHASH_SINGLE + SIGHASH_ANYONECANPAY) // 11000011
    }

    public struct BTC {
        public static let ALL: SighashType = SighashType(SIGHASH_ALL) // 00000001
        public static let NONE: SighashType = SighashType(SIGHASH_NONE) // 00000010
        public static let SINGLE: SighashType = SighashType(SIGHASH_SINGLE) // 00000011
        public static let ALL_ANYONECANPAY: SighashType = SighashType(SIGHASH_ALL + SIGHASH_ANYONECANPAY) // 10000001
        public static let NONE_ANYONECANPAY: SighashType = SighashType(SIGHASH_NONE + SIGHASH_ANYONECANPAY) // 10000010
        public static let SINGLE_ANYONECANPAY: SighashType = SighashType(SIGHASH_SINGLE + SIGHASH_ANYONECANPAY) // 10000011
    }
}

extension UInt8 {
    public init(_ hashType: SighashType) {
        self = hashType.uint8
    }
}

extension UInt32 {
    public init(_ hashType: SighashType) {
        self = UInt32(UInt8(hashType))
    }
}
