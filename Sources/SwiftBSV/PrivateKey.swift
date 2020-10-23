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

    /// The raw private key data
    var data: Data {
        return bn.data
    }

    /// Return the associated Public Key
    var publicKey: PublicKey {
        let publicKeyData = Crypto.computePublicKey(fromPrivateKey: data, compressed: true)
        return PublicKey(fromDer: publicKeyData)!
    }

    var address: Address {
        return Address(self, network: network)
    }

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

    public init(data: Data, network: Network = .mainnet) {
        let number = BInt(data: data)
        self.init(bn: number, network: network)
    }

    public init(bn: BInt, isCompressed: Bool = true, network: Network = .mainnet) {
        self.bn = bn
        self.network = network
        self.isCompressed = isCompressed
    }

    public init(buffer: Data, network: Network = .mainnet) {
        if buffer.count == 1 + 32 + 1 && buffer[1 + 32 + 1 - 1] == 1 {
            isCompressed = true
        } else if buffer.count == 1 + 32 {
            isCompressed = false
        } else {
            fatalError("PrivateKey: Invalid length of data. Must be 33 for uncompressed, or 34 for compressed priv key")
        }

        if buffer[0] != network.privateKeyVersionByteNum {
            fatalError("PrivateKey: Invalid private key version number")
        }

        let data = buffer[1..<33]

//        let string = data.hex
//        let bn = BInt(str: string, radix: 16)!
        let bn = BInt(data: data)

        self.bn = bn
        self.network = network
    }

    public init?(wif: String, network: Network = .mainnet) {
        guard let data = Base58Check.decode(wif) else {
            return nil
        }

        self.init(buffer: data, network: network)
    }

    /// Return the Wif encoded string
    public func toWif() -> String {
        Base58Check.encode(toWifData())
    }

    /// Return the Wif encoded data
    func toWifData() -> Data {
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

}
