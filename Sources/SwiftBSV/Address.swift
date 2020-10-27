//
//  Address.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-19.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

public struct Address {

    let network: Network
    let versionByteNum: UInt8
    let hashBuffer: Data

    /// Create an Address from an existing Public Key
    public init(_ publicKey: PublicKey, network: Network = .mainnet, compressed: Bool? = nil) {
        self.network = network
        self.hashBuffer = Crypto.sha256ripemd160(publicKey.toDer(compressed: compressed))
        self.versionByteNum = network.address.publicKeyHash
    }

    /// Create an Address from an existing Private Key
    public init(_ privateKey: PrivateKey, network: Network = .mainnet) {
        self.network = network
        self.hashBuffer = Crypto.sha256ripemd160(privateKey.publicKey.toDer())
        self.versionByteNum = network.address.publicKeyHash
    }

    public init(_ bip32: Bip32, network: Network = .mainnet) {
        self.init(bip32.publicKey, network: network)
    }

    /// Create an Address from an address string
    ///
    /// E.g. "157w5uZoW6YsWhiEbKxhUNEnkXXu9t4sr3"
    ///
    public init?(fromString string: String, network: Network = .mainnet) {
        guard let buffer = Base58Check.decode(string) else {
            return nil
        }
        self.init(buffer: buffer, network: network)
    }

    init?(buffer: Data, network: Network = .mainnet) {
        guard buffer.count == 1 + 20 else {
            return nil
        }

        guard buffer[0] == network.address.publicKeyHash else {
            return nil
        }

        self.network = network
        self.versionByteNum = buffer[0]
        self.hashBuffer = buffer.suffix(from: 1)
    }

    /// Returns the raw buffer of the Address
    func toBuffer() -> Data {
        var data = Data()
        data += versionByteNum
        data += hashBuffer
        return data
    }

    /// Returns the Address string
    public func toString() -> String {
        Base58Check.encode(toBuffer())
    }

}

extension Address: CustomStringConvertible {
    public var description: String {
        return toString()
    }
}

// MARK: - Address+Script

extension Address {
    /// Return the P2PKH script from this address
    public func toTxOutputScript() -> Script {
        return Script.buildPublicKeyHashOut(pubKeyHash: hashBuffer)
    }

}
