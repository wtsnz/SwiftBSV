//
//  Network.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

/// The Bitcoin SV Network configuration
public enum Network {

    /// The BitcoinSV Main Network
    case mainnet

    /// The BitcoinSV Test Network
    case testnet


    public var bip32: Bip32 {
        switch self {
        case .mainnet:
            return .init(pubKey: 0x0488b21e, privKey: 0x0488ade4)
        case .testnet:
            return .init(pubKey: 0x043587cf, privKey: 0x04358394)
        }
    }

    public var address: Address {
        switch self {
        case .mainnet:
            return Address(publicKeyHash: 0x00)
        case .testnet:
            return Address(publicKeyHash: 0x6f)
        }
    }

    public var txBuilder: TxBuilder {
        return TxBuilder(dust: 546, feePerKb: 0.00000500e8)
    }

    public struct Bip32 {
        var pubKey: UInt32
        var privKey: UInt32
    }
    public struct Address {
        let publicKeyHash: UInt8
    }

    public struct TxBuilder {
        let dust: UInt64
        let feePerKb: Float
    }









    // P2PKH
    public var publicKeyHash: UInt8 {
        switch self {
        case .mainnet:
            return 0x00
        case .testnet:
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
        case .mainnet:
            return 0x80
        case .testnet:
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
        case .mainnet:
            return 0
        case .testnet:
            return 0
        }
    }
    
    public var scheme: String {
        switch self {
        case .mainnet:
            return "bitcoin"
        case .testnet:
            return "bitcoin"
        }
    }
}
