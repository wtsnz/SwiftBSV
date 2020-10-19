//
//  Network.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

public enum Network {

    case bitcoin
    case bitcoinTestnet

    public struct Bip32 {
        var pubKey: UInt32
        var privKey: UInt32
    }

    public var bip32: Bip32 {
        switch self {
        case .bitcoin:
            return .init(pubKey: 0x0488b21e, privKey: 0x0488ade4)
        case .bitcoinTestnet:
            return .init(pubKey: 0x043587cf, privKey: 0x04358394)
        }
    }

    // P2PKH
    public var publicKeyHash: UInt8 {
        switch self {
        case .bitcoin:
            return 0x00
        case .bitcoinTestnet:
            return 0x6f
        }
    }
    
    // P2SH
//    public var scriptHash: UInt8 {
//        switch self {
//        case .bitcoin:
//            return 0x05
//        case .bitcoinTestnet:
//            return
//        }
//    }
    
    //https://www.reddit.com/r/litecoin/comments/6vc8tc/how_do_i_convert_a_raw_private_key_to_wif_for/
    /// PrivKey versionByteNum
    public var privateKeyVersionByteNum: UInt8 {
        switch self {
        case .bitcoin:
            return 0x80
        case .bitcoinTestnet:
            return 0xef
        }
    }
    
    public var addressPrefix: String {
        return ""
    }
    
    public var uncompressedPkSuffix: UInt8 {
        return 0x01
    }
    
    public var coinType: UInt32 {
        switch self {
        case .bitcoin:
            return 0
        case .bitcoinTestnet:
            return 0
        }
    }
    
    public var scheme: String {
        switch self {
        case .bitcoin:
            return "bitcoin"
        case .bitcoinTestnet:
            return "bitcoin"
        }
    }
}
