//
//  PrivateKey.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

public struct PrivateKey {

    /// The BInt of the private key
    public let bn: BInt

    /// Whether the PrivateKey was inialized from a compressed source.
    private let isCompressed: Bool

    /// The Bitcoin Network this PrivateKey belongs to.
    public let network: Network

    public init(network: Network = .mainnet) {
        var buffer: Data
        var number: BInt
        var condition: Bool
        repeat {
            buffer = Data.randomBytes(length: 32)
            number = BInt(data: buffer)
            condition = number < Point.N
        } while (!condition)

        self.bn = number
        self.isCompressed = true
        self.network = network
    }

    public init(bn: BInt, isCompressed: Bool = true, network: Network = .mainnet) {
        self.bn = bn
        self.network = network
        self.isCompressed = isCompressed
    }

    public init(data: Data, network: Network = .mainnet) {
        if data.count == 1 + 32 + 1 && data[1 + 32 + 1 - 1] == 1 {
            isCompressed = true
        } else if data.count == 1 + 32 {
            isCompressed = false
        } else {
            fatalError("PrivateKey: Invalid length of data. Must be 33 for uncompressed, or 34 for compressed priv key")
        }

        if data[0] != network.privateKeyVersionByteNum {
            fatalError("PrivateKey: Invalid private key version number")
        }

        let buffer = data[1..<33]
        let bn = BInt(data: buffer)

        self.bn = bn
        self.network = network
    }

    public init?(wif: String, network: Network = .mainnet) {
        guard let data = Base58Check.decode(wif) else {
            return nil
        }

        self.init(data: data, network: network)
    }

    public func toData() -> Data {
        var data = Data()
        data += network.privateKeyVersionByteNum

        if isCompressed {
            data += self.bn.data
            data += UInt8(0x01)
        } else {
            data += self.bn.data
        }

        return data
    }

    public func toWif() -> String {
        Base58Check.encode(toData())
    }

}
