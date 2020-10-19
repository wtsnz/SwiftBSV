//
//  Bip32.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import secp256k1

/**
 * Bip32: HD Wallets
 * =================
 *
 * Bip32 is hierarchical deterministic wallets
 */

public struct Bip32 {

    public enum DerivationNode {
        case hardened(UInt32)
        case notHardened(UInt32)

        public var index: UInt32 {
            switch self {
            case .hardened(let index):
                return index
            case .notHardened(let index):
                return index
            }
        }

        public var hardened: Bool {
            switch self {
            case .hardened:
                return true
            case .notHardened:
                return false
            }
        }
    }

    let network: Network

    let versionPrefix: UInt32
    let depth: UInt8
    let fingerprint: UInt32
    let childIndex: UInt32
    let chainCode: Data

    let privateKey: PrivateKey?
    let publicKey: PublicKey

    /// Create a Bip32 HD Key from an existing Seed
    public init(seed: Data, network: Network = .mainnet) {
        let output = Crypto.hmacsha512(key: "Bitcoin seed".data(using: .ascii)!, data: seed)
        let privateKey = output[0..<32]
        let chainCode = output[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, network: network)
    }

    /// Create a Bip32 HD Key from an extended key string
    ///
    /// These look something like this
    /// "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    ///
    /// - Parameter string: The extended key string
    public init?(string: String) {
        guard let buffer = Base58Check.decode(string) else {
            return nil
        }
        self.init(buffer, network: .mainnet)
    }

    public init?(_ data: Data, network: Network = .mainnet) {
        self.network = network

        guard data.count == 78 else { return nil }

        versionPrefix = data[0..<4].to(type: UInt32.self).bigEndian
        depth = data[4..<5].bytes[0]
        fingerprint = data[5..<9].to(type: UInt32.self)
        childIndex = data[9..<13].to(type: UInt32.self)
        chainCode = data[13..<45]

        let isPrivate = self.versionPrefix == network.bip32.privKey
        let isPublic = self.versionPrefix == network.bip32.pubKey

        let keyBytes = Data(data[45..<78])

        if (isPrivate == true) && (keyBytes[0] == 0x0) {

            // keyBytes contains a Private Key (32 Bytes)
            let privateKeyBytes = keyBytes[1..<33]
            let privateKeyNumber = BInt(data: privateKeyBytes)
            privateKey = PrivateKey(bn: privateKeyNumber, network: network)
            publicKey = privateKey!.publicKey

        } else if isPublic == true && (keyBytes[0] == 0x02 || keyBytes[0] == 0x03) {
            // keyBytes contains a Compressed Public Key (33 Bytes)
            privateKey = nil
            publicKey = PublicKey(fromDer: keyBytes)!
        } else {
            return nil
        }
    }

    init(privateKey: Data, chainCode: Data, network: Network = .mainnet) {
        self.init(privateKey: privateKey, chainCode: chainCode, network: network, depth: 0, fingerprint: 0, childIndex: 0)
    }

    init(privateKey: Data, chainCode: Data, network: Network, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.chainCode = chainCode
        self.network = network
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
        self.versionPrefix = network.bip32.privKey

        self.privateKey = PrivateKey(bn: BInt(data: privateKey), network: network)
        self.publicKey = self.privateKey!.publicKey
    }

    init(publicKey: Data, chainCode: Data, network: Network, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.chainCode = chainCode
        self.network = network
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
        self.versionPrefix = network.bip32.pubKey

        privateKey = nil
        self.publicKey = PublicKey(fromDer: publicKey)!
    }

    /// Returns the extended key as a string
    public func toString() -> String {
        Base58Check.encode(toData())
    }

    /// Converts this Bip32 PrivateKey into the Bip32 PublicKey version
    func toPublic() -> Bip32 {
        if versionPrefix == network.bip32.pubKey {
            return self
        }

        return Bip32(publicKey: publicKey.toDer(), chainCode: chainCode, network: network, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
    }

    public func toData() -> Data {

        var extendedPrivateKeyData = Data()

        switch self.versionPrefix {
        case network.bip32.privKey:
            extendedPrivateKeyData += versionPrefix.bigEndian
            extendedPrivateKeyData += depth.littleEndian
            extendedPrivateKeyData += fingerprint.littleEndian
            extendedPrivateKeyData += childIndex.littleEndian
            extendedPrivateKeyData += chainCode
            extendedPrivateKeyData += UInt8(0)
            extendedPrivateKeyData += privateKey!.data
        case network.bip32.pubKey:
            extendedPrivateKeyData += versionPrefix.bigEndian
            extendedPrivateKeyData += depth.littleEndian
            extendedPrivateKeyData += fingerprint.littleEndian
            extendedPrivateKeyData += childIndex.littleEndian
            extendedPrivateKeyData += chainCode
            extendedPrivateKeyData += publicKey.toDer()
        default:
            fatalError("Bip32: Invalid version byte")
        }

        return extendedPrivateKeyData
    }

    public func derived(at node: DerivationNode) -> Bip32? {

        if (0x80000000 & node.index) != 0 {
            fatalError("Bip32: invalid child index")
        }

        guard let derrived = _HDKey(
            privateKey: privateKey?.data,
            publicKey: publicKey.toDer(),
            chainCode: chainCode,
            depth: depth,
            fingerprint: fingerprint,
            childIndex: childIndex
        )
        .derived(
            at: node.index,
            hardened: node.hardened
        ) else { return nil }

        switch self.versionPrefix {
        case network.bip32.privKey:
            return Bip32(privateKey: derrived.privateKey!, chainCode: derrived.chainCode, network: network, depth: derrived.depth, fingerprint: derrived.fingerprint, childIndex: derrived.childIndex)
        case network.bip32.pubKey:
            return Bip32(publicKey: derrived.publicKey, chainCode: derrived.chainCode, network: network, depth: derrived.depth, fingerprint: derrived.fingerprint, childIndex: derrived.childIndex)
        default:
            fatalError("Bip32: Invalid version byte")
        }

    }

    public func derivedKey(path: String) -> Bip32? {
        var key: Bip32? = self

        var path = path
        if path == "m" || path == "/" || path == "" {
            return key
        }
        if path.contains("m/") {
            path = String(path.dropFirst(2))
        }
        for chunk in path.split(separator: "/") {
            var hardened = false
            var indexText = chunk
            if chunk.contains("'") {
                hardened = true
                indexText = indexText.dropLast()
            }
            guard let index = UInt32(indexText) else {
                fatalError("Bip32: invalid path")
            }

            key = key?.derived(at: hardened ? .hardened(index) : .notHardened(index))
        }
        return key
    }

}

extension Bip32: CustomStringConvertible {
    public var description: String {
        return toString()
    }
}

//extension PrivateKey {
//
//    public init?(bip32: Bip32) {
//        guard let data = bip32.privateKey else {
//            return nil
//        }
//
//        self.init(data: data)
//    }
//
//}

//
//  BitcoinKitPrivateSwift.swift
//
//  Copyright © 2019 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

class _HDKey {
    private(set) var privateKey: Data?
    private(set) var publicKey: Data
    private(set) var chainCode: Data
    private(set) var depth: UInt8
    private(set) var fingerprint: UInt32
    private(set) var childIndex: UInt32

    init(privateKey: Data?, publicKey: Data, chainCode: Data, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    func derived(at childIndex: UInt32, hardened: Bool) -> _HDKey? {
        var data = Data()
        if hardened {
            data.append(0)
            guard let privateKey = self.privateKey else {
                return nil
            }
            data.append(privateKey)
        } else {
            data.append(publicKey)
        }
        var childIndex = CFSwapInt32HostToBig(hardened ? (0x80000000 as UInt32) | childIndex : childIndex)
        data.append(Data(bytes: &childIndex, count: MemoryLayout<UInt32>.size))

        let digest = Crypto.hmacsha512(key: chainCode, data: data)
        let derivedPrivateKey: [UInt8] = digest[0..<32].map { $0 }
        let derivedChainCode: [UInt8] = digest[32..<64].map { $0 }
        var result: Data
        if let privateKey = self.privateKey {
            guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
                return nil
            }
            defer { secp256k1_context_destroy(ctx) }
            var privateKeyBytes = privateKey.map { $0 }
            var derivedPrivateKeyBytes = derivedPrivateKey.map { $0 }
            if secp256k1_ec_privkey_tweak_add(ctx, &privateKeyBytes, &derivedPrivateKeyBytes) == 0 {
                return nil
            }
            result = Data(privateKeyBytes)
        } else {
            guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
                return nil
            }
            defer { secp256k1_context_destroy(ctx) }
            let publicKeyBytes: [UInt8] = publicKey.map { $0 }
            var secpPubkey = secp256k1_pubkey()
            if secp256k1_ec_pubkey_parse(ctx, &secpPubkey, publicKeyBytes, publicKeyBytes.count) == 0 {
                return nil
            }
            if secp256k1_ec_pubkey_tweak_add(ctx, &secpPubkey, derivedPrivateKey) == 0 {
                return nil
            }
            var compressedPublicKeyBytes = [UInt8](repeating: 0, count: 33)
            var compressedPublicKeyBytesLen = 33
            if secp256k1_ec_pubkey_serialize(ctx, &compressedPublicKeyBytes, &compressedPublicKeyBytesLen, &secpPubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 0 {
                return nil
            }
            result = Data(compressedPublicKeyBytes)
        }

        let fingerPrint: UInt32 = Crypto.sha256ripemd160(publicKey).to(type: UInt32.self)
        return _HDKey(privateKey: result, publicKey: result, chainCode: Data(derivedChainCode), depth: self.depth + 1, fingerprint: fingerPrint, childIndex: childIndex)
    }
}
