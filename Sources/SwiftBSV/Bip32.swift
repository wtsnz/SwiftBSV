//
//  Bip32.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import CommonCrypto
import CryptoSwift
import secp256k1

/**
 * Bip32: HD Wallets
 * =================
 *
 * Bip32 is hierarchical deterministic wallets
 */


extension UInt32 {
    public func serialize32() -> Data {
        let uint32 = UInt32(self)
        var bigEndian = uint32.bigEndian
        let count = MemoryLayout<UInt32>.size
        let bytePtr = withUnsafePointer(to: &bigEndian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        let byteArray = Array(bytePtr)
        return Data(byteArray)
    }
}

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

public final class Bip32 {

    public let depth: UInt8
    public let fingerprint: Data
    public let childIndex: UInt32

    let chainCode: Data

    public let network: Network

    // The type of key (pub/priv)
    public var versionPrefix: Data

    public var privateKey: Data? = nil
    public var publicKey: Data

    public convenience init(seed: Data, network: Network = .bitcoin) {
        let output = Crypto.HMACSHA512(key: "Bitnetwork seed".data(using: .ascii)!, data: seed)
        let privateKey = output[0..<32]
        let chainCode = output[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, network: network)
    }

    public convenience init(privateKey: Data, chainCode: Data, network: Network = .bitcoin) {
        let publicKey = Crypto.generatePublicKey(data: privateKey, compressed: true)
        self.init(privateKey: privateKey, publicKey: publicKey, chainCode: chainCode, network: network, depth: 0, fingerprint: Data(hex: "000000"), childIndex: 0)
    }

    init(privateKey: Data, publicKey: Data, chainCode: Data, network: Network, depth: UInt8, fingerprint: Data, childIndex: UInt32) {
        self.privateKey = privateKey
        self.publicKey = publicKey//_SwiftKey.computePublicKey(fromPrivateKey: privateKey, compression: true)
        self.chainCode = chainCode
        self.network = network
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
        self.versionPrefix = network.bip32.privKey
    }

    init(publicKey: Data, chainCode: Data, network: Network, depth: UInt8, fingerprint: Data, childIndex: UInt32) {
        self.privateKey = nil
        self.chainCode = chainCode
        self.network = network
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
        self.versionPrefix = network.bip32.pubKey
        self.publicKey = publicKey
    }

    public init?(_ data: Data, network: Network = .bitcoin) {
        self.network = network

        guard data.count == 78 else { return nil }

//        self.versionPrefix = data[0..<4]

        func getUInt32(data: Data) -> UInt32 {
            let bigEndianUInt32 = data.withUnsafeBytes { $0.load(as: UInt32.self) }
            let value = CFByteOrderGetCurrent() == CFByteOrder(CFByteOrderLittleEndian.rawValue)
                ? UInt32(bigEndian: bigEndianUInt32)
                : bigEndianUInt32

            return value
        }

        let bigEndianUInt32 = data[0..<4].withUnsafeBytes { $0.load(as: UInt32.self) }
        let value = CFByteOrderGetCurrent() == CFByteOrder(CFByteOrderLittleEndian.rawValue)
            ? UInt32(bigEndian: bigEndianUInt32)
            : bigEndianUInt32

        let aa = Data(data[0..<4].reversed()).to(type: UInt32.self)
        let a = data[0..<4].withUnsafeBytes { $0.load(as: UInt32.self) }

        versionPrefix = data[0..<4]


//        self.versionPrefix = UnsafePointer(data[0..<4].bytes).withMemoryRebound(to: UInt32.self, capacity: 1) {
//            $0.pointee
//        }

        self.depth = data[4..<5].bytes[0]

        fingerprint = data[5..<9]

        childIndex = getUInt32(data: data[9..<13])

//        self.fingerprint = UnsafePointer(data[5..<9].bytes).withMemoryRebound(to: UInt32.self, capacity: 1) {
//            $0.pointee
//        }
//
//        self.childIndex = UnsafePointer(data[9..<13].bytes).withMemoryRebound(to: UInt32.self, capacity: 1) {
//            $0.pointee
//        }
        self.chainCode = data[13..<45]

        let isPrivate = self.versionPrefix == network.bip32.privKey
        let isPublic = self.versionPrefix == network.bip32.pubKey

        let keyBytes = Data(data[45..<78])

        if (isPrivate == true) && (keyBytes[0] == 0x0) {

            privateKey = keyBytes[1..<33]
//            privateKey = PrivateKey2(privateKey: keyBytes[1..<33], network: network)

            let pubKey = _SwiftKey.computePublicKey(fromPrivateKey: privateKey!, compression: true)
//            let pubKey = Crypto.generatePublicKey(data: privateKey!, compressed: true)

//            let pubKey = PublicKey(privateKey: privateKey!.raw)
            publicKey = pubKey
        } else if isPublic == true && (keyBytes[0] == 0x02 || keyBytes[0] == 0x03) {
            publicKey = data[45..<78]
        } else {
            return nil
        }

    }

    func toPublic() -> Bip32 {
        if versionPrefix == network.bip32.pubKey {
            return self
        }

        return Bip32(publicKey: publicKey, chainCode: chainCode, network: network, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
    }

//    public convenience init?(_ serializedString: String) {
//        guard let data = Base58.decode(serializedString) else { return }
//        self.init(data: data)
//    }
//
//    public init(data: Data) {
//        //        guard seed.count >= 16 else {return nil}
//        //        let hmacKey = "Bitnetwork seed".data(using: .ascii)!
//        //        let hmac:Authenticator = HMAC(key: hmacKey.bytes, variant: HMAC.Variant.sha512)
//        //        guard let entropy = try? hmac.authenticate(seed.bytes) else {return nil}
//        //        guard entropy.count == 64 else { return nil}
//        //        let I_L = entropy[0..<32]
//        //        let I_R = entropy[32..<64]
//        //        chaincode = Data(I_R)
//        //        let privKeyCandidate = Data(I_L)
//        //        guard SECP256K1.verifyPrivateKey(privateKey: privKeyCandidate) else {return nil}
//        //        guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: privKeyCandidate, compressed: true) else {return nil}
//        //        guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else {return nil}
//        //        publicKey = pubKeyCandidate
//        //        privateKey = privKeyCandidate
//        //        depth = 0x00
//        //        childNumber = UInt32(0)
//    }

//    public func wifCompressed() -> String {
//        var data = Data()
//        data += network.wifAddressPrefix
//        data += raw
//        data += UInt8(0x01)
//        data += data.doubleSHA256.prefix(4)
//        return Base58.encode(data)
//    }
//
//    public func wifUncompressed() -> String {
//        var data = Data()
//        data += network.wifAddressPrefix
//        data += raw
//        data += data.doubleSHA256.prefix(4)
//        return Base58.encode(data)
//    }

    // To extended string
    public func toString() -> String {

        var extendedPrivateKeyData = Data()

        switch self.versionPrefix {
        case network.bip32.privKey:
            extendedPrivateKeyData += versionPrefix
            extendedPrivateKeyData += depth.littleEndian
            extendedPrivateKeyData += fingerprint
            extendedPrivateKeyData += childIndex.littleEndian
            extendedPrivateKeyData += chainCode
            extendedPrivateKeyData += UInt8(0)
            extendedPrivateKeyData += privateKey!
        case network.bip32.pubKey:
            extendedPrivateKeyData += versionPrefix
            extendedPrivateKeyData += depth.littleEndian
            extendedPrivateKeyData += fingerprint
            extendedPrivateKeyData += childIndex.littleEndian
            extendedPrivateKeyData += chainCode
            extendedPrivateKeyData += publicKey
        default:
            fatalError("Bip32: Invalid version byte")
        }

        return Base58Check.encode(extendedPrivateKeyData)
    }

//    func deriveChild(at node: DerivationNode) -> Bip32 {
//
//        let edge: UInt32 = 0x80000000
//        guard (edge & node.index) == 0 else { fatalError("Invalid child index") }
//
//        let usePrivate = (node.index & 0x80000000)  != 0
//        let isPrivate = versionPrefix == network.bip32.privKey
//
//        if usePrivate && (privateKey == nil || !isPrivate) {
//            fatalError("Cannot do private key derivation without private key")
//        }
//
//        var ib = Data()
//
//        if let privateKey = privateKey {
//
//            var data = Data()
//
//            if usePrivate {
//                data += 0
//                privateKey.raw
//                data += (i >> 24) & 0xff
//            }
//
//        } else {
//
//        }
//    }


//    private static var curveOrder = BInt(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!
//    public static var defaultPath: String = "m/44'/60'/0'/0"
//    public static var defaultPathPrefix: String = "m/44'/60'/0'"
//    public static var defaultPathMetamask: String = "m/44'/60'/0'/0/0"
//    public static var defaultPathMetamaskPrefix: String = "m/44'/60'/0'/0"
//    public static var hardenedIndexPrefix: UInt32 = (UInt32(1) << 31)

//    private init(
//        chainCode: Data,
//        depth: UInt8,
//        publicKey: Data,
//        privateKey: PrivateKey2?,
//        childNumber: UInt32,
//        parentFingerprint: Data,
//        versionPrefix: Data,
//        network: Network = .bitnetwork
//    ) {
//        self.chainCode = chainCode
//        self.depth = depth
//        self.publicKey = publicKey
//        self.privateKey = privateKey
//        self.childNumber = childNumber
//        self.parentFingerprint = parentFingerprint
//        self.versionPrefix = versionPrefix
//        self.network = network
////
////        let newNode = HDNode()
////        newNode.chaincode = cc
////        newNode.depth = self.depth + 1
////        newNode.publicKey = pubKeyCandidate
////        newNode.privateKey = privKeyCandidate
////        newNode.childNumber = trueIndex
////
////        guard let fprint = try? RIPEMD160.hash(self.publicKey.sha256())[0..<4] else {
////            return nil
////        }
////        newNode.parentFingerprint = fprint
//    }

//    public func derive(index: UInt32, derivePrivateKey: Bool, hardened: Bool = false) -> Bip32? {
//        if derivePrivateKey {
//            if self.hasPrivate { // derive private key when is itself extended private key
//                var entropy: Array<UInt8>
//                var trueIndex: UInt32
//                if index >= (UInt32(1) << 31) || hardened {
//                    trueIndex = index;
//                    if trueIndex < (UInt32(1) << 31) {
//                        trueIndex = trueIndex + (UInt32(1) << 31)
//                    }
//
//                    var inputForHMAC = Data()
//                    inputForHMAC.append(Data([UInt8(0x00)]))
//                    inputForHMAC.append(self.privateKey!.raw)
//                    inputForHMAC.append(trueIndex.serialize32())
//
//                    let ent = Crypto.HMACSHA512(key: chainCode, data: inputForHMAC)
//
////                    let hmac: Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
//
////                    guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
//                    guard ent.count == 64 else { return nil }
//
//                    entropy = ent.bytes
//
//                } else {
//                    trueIndex = index
////                    let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
//                    var inputForHMAC = Data()
//                    inputForHMAC.append(self.publicKey)
//                    inputForHMAC.append(trueIndex.serialize32())
//
//                    let ent = Crypto.HMACSHA512(key: chainCode, data: inputForHMAC)
//
////                    guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
//                    guard ent.count == 64 else { return nil }
//                    entropy = ent.bytes
//                }
//                let I_L = entropy[0..<32]
//                let I_R = entropy[32..<64]
//                let cc = Data(I_R)
//
//                let bn = BInt(data: Data(I_L))
////                let bn = BigUInt(Data(I_L))
//
//                if bn > Bip32.curveOrder {
//                    if trueIndex < UInt32.max {
//                        return self.derive(index: index+1, derivePrivateKey: derivePrivateKey, hardened: hardened)
//                    }
//                    return nil
//                }
//                let newPK = (bn + BInt(data: self.privateKey!.raw)) % Bip32.curveOrder
////                let newPK = (bn + BigUInt(self.privateKey!)) % HDNode.curveOrder
//                if newPK == BInt(0) {
//                    if trueIndex < UInt32.max {
//                        return self.derive(index: index + 1, derivePrivateKey: derivePrivateKey, hardened: hardened)
//                    }
//                    return nil
//                }
//                guard let privKeyCandidate = newPK.serialize().setLengthLeft(32) else {return nil}
////                guard SECP256K1.verifyPrivateKey(privateKey: privKeyCandidate) else {return nil }
//
//                let encrypter = EllipticCurveEncrypterSecp256k1()
//                guard ((try? encrypter.verifyPrivateKey(privateKey: privKeyCandidate) == true) != nil) else { return nil }
//
//                guard let pubKeyCandidate = try? encrypter.privateToPublic(privateKey: privKeyCandidate, compressed: true) else { return nil }
//                guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else { return nil }
//                guard self.depth < UInt8.max else { return nil }
//
//                let fprint = RIPEMD160.hash(self.publicKey.sha256())[0..<4]
//
//                return Bip32.init(
//                    chainCode: cc,
//                    depth: depth + 1,
//                    publicKey: pubKeyCandidate,
//                    privateKey: PrivateKey2(privateKey: privKeyCandidate, network: network),
//                    childNumber: trueIndex,
//                    parentFingerprint: fprint,
//                    versionPrefix: versionPrefix,
//                    network: network
//                )
//
//            } else {
//                return nil // derive private key when is itself extended public key (impossible)
//            }
//        }
//        else { // deriving only the public key
////            var entropy:Array<UInt8> // derive public key when is itself public key
////            if index >= (UInt32(1) << 31) || hardened {
////                return nil // no derivation of hardened public key from extended public key
////            } else {
////                let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
////                var inputForHMAC = Data()
////                inputForHMAC.append(self.publicKey)
////                inputForHMAC.append(index.serialize32())
////                guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
////                guard ent.count == 64 else { return nil }
////                entropy = ent
////            }
////            let I_L = entropy[0..<32]
////            let I_R = entropy[32..<64]
////            let cc = Data(I_R)
////            let bn = BigUInt(Data(I_L))
////            if bn > HDNode.curveOrder {
////                if index < UInt32.max {
////                    return self.derive(index:index+1, derivePrivateKey: derivePrivateKey, hardened:hardened)
////                }
////                return nil
////            }
////            guard let tempKey = bn.serialize().setLengthLeft(32) else {return nil}
////            guard SECP256K1.verifyPrivateKey(privateKey: tempKey) else {return nil }
////            guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: tempKey, compressed: true) else {return nil}
////            guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else {return nil}
////            guard let newPublicKey = SECP256K1.combineSerializedPublicKeys(keys: [self.publicKey, pubKeyCandidate], outputCompressed: true) else {return nil}
////            guard newPublicKey.bytes[0] == 0x02 || newPublicKey.bytes[0] == 0x03 else {return nil}
////            guard self.depth < UInt8.max else {return nil}
////            let newNode = HDNode()
////            newNode.chaincode = cc
////            newNode.depth = self.depth + 1
////            newNode.publicKey = pubKeyCandidate
////            newNode.childNumber = index
////            guard let fprint = try? RIPEMD160.hash(message: self.publicKey.sha256())[0..<4] else {
////                return nil
////            }
////            newNode.parentFingerprint = fprint
////            var newPath = String()
////            if newNode.isHardened {
////                newPath = self.path! + "/"
////                newPath += String(newNode.index % HDNode.hardenedIndexPrefix) + "'"
////            } else {
////                newPath = self.path! + "/" + String(newNode.index)
////            }
////            newNode.path = newPath
////            return newNode
//        }
//        return nil
//    }

    public func derived(at node: DerivationNode) -> Bip32? {

        if (0x80000000 & node.index) != 0 {
            fatalError("invalid child index")
        }

        guard let derrived = _HDKey(
                privateKey: privateKey,
                publicKey: publicKey,
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
            return Bip32(privateKey: derrived.privateKey!, publicKey: derrived.publicKey, chainCode: derrived.chainCode, network: network, depth: derrived.depth, fingerprint: derrived.fingerprint, childIndex: derrived.childIndex)
        case network.bip32.pubKey:
            return Bip32(publicKey: derrived.publicKey, chainCode: derrived.chainCode, network: network, depth: derrived.depth, fingerprint: derrived.fingerprint, childIndex: derrived.childIndex)
        default:
            fatalError("Bip32: Invalid version byte")
        }

    }
//
//        let edge: UInt32 = 0x80000000
//        guard (edge & node.index) == 0 else { fatalError("Invalid child index") }
//
//        let raw = privateKey!
//
//        var data = Data()
//        switch node {
//        case .hardened:
//            data += UInt8(0)
//            data += raw
//        case .notHardened:
//            data += Crypto.generatePublicKey(data: raw, compressed: true)
//        }
//
//        let derivingIndex = CFSwapInt32BigToHost(node.hardens ? (edge | node.index) : node.index)
//        data += derivingIndex
//
//        let digest = Crypto.HMACSHA512(key: chainCode, data: data)
//        let factor = BInt(data: digest[0..<32])
//
//        let curveOrder = BInt(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!
//        let derivedPrivateKey = ((BInt(data: raw) + factor) % curveOrder).data
//        let derivedChainCode = digest[32..<64]
//
//        return Bip32(
//            privateKey: derivedPrivateKey,
//            chainCode: derivedChainCode,
//            childIndex: derivingIndex,
//            network: network
//        )
//    }

}


//public final class Bip32_no {
//
//    public struct HDversion {
//        public var privatePrefix: Data = Data.fromHex("0x0488ADE4")!
//        public var publicPrefix: Data = Data.fromHex("0x0488B21E")!
//        public init() {
//
//        }
//    }
//
//    public var path: String? = "m"
//    public var privateKey: Data? = nil
//    public var publicKey: Data
//    public var chaincode: Data
//    public var depth: UInt8
//    public var parentFingerprint: Data = Data(repeating: 0, count: 4)
//    public var childNumber: UInt32 = UInt32(0)
//    public var isHardened:Bool {
//        get {
//            return self.childNumber >= (UInt32(1) << 31)
//        }
//    }
//    public var index: UInt32 {
//        get {
//            if self.isHardened {
//                return self.childNumber - (UInt32(1) << 31)
//            } else {
//                return self.childNumber
//            }
//        }
//    }
//    public var hasPrivate:Bool {
//        get {
//            return privateKey != nil
//        }
//    }
//
//    init() {
//        publicKey = Data()
//        chaincode = Data()
//        depth = UInt8(0)
//    }
//
//    public convenience init?(_ serializedString: String) {
//        guard let data = Base58.decode(serializedString) else { return nil }
//        self.init(data)
//    }
//
//    public init?(_ data: Data) {
//        guard data.count == 82 else {return nil}
//        let header = data[0..<4]
//        var serializePrivate = false
//        if header == Bip32.HDversion().privatePrefix {
//            serializePrivate = true
//        }
//        depth = data[4..<5].bytes[0]
//        parentFingerprint = data[5..<9]
//        let cNum = data[9..<13].bytes
//        childNumber = UnsafePointer(cNum).withMemoryRebound(to: UInt32.self, capacity: 1) {
//            $0.pointee
//        }
//        chaincode = data[13..<45]
//        if serializePrivate {
//            privateKey = data[46..<78]
//
//            let pubKey = PublicKey(privateKey: privateKey!)
//
////            guard let pubKey = Web3.Utils.privateToPublic(privateKey!, compressed: true) else {return nil}
//            if pubKey.data[0] != 0x02 && pubKey.data[0] != 0x03 {return nil}
//            publicKey = pubKey
//        } else {
//            publicKey = data[45..<78]
//        }
//        let hashedData = data[0..<78].sha256().sha256()
//        let checksum = hashedData[0..<4]
//        if checksum != data[78..<82] {return nil}
//    }
//
//    public init?(seed: Data) {
//        guard seed.count >= 16 else {return nil}
//        let hmacKey = "Bitcoin seed".data(using: .ascii)!
//        let hmac:Authenticator = HMAC(key: hmacKey.bytes, variant: HMAC.Variant.sha512)
//        guard let entropy = try? hmac.authenticate(seed.bytes) else {return nil}
//        guard entropy.count == 64 else { return nil}
//        let I_L = entropy[0..<32]
//        let I_R = entropy[32..<64]
//        chaincode = Data(I_R)
//        let privKeyCandidate = Data(I_L)
//        guard SECP256K1.verifyPrivateKey(privateKey: privKeyCandidate) else {return nil}
//        guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: privKeyCandidate, compressed: true) else {return nil}
//        guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else {return nil}
//        publicKey = pubKeyCandidate
//        privateKey = privKeyCandidate
//        depth = 0x00
//        childNumber = UInt32(0)
//    }
//
//    private static var curveOrder = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
//    public static var defaultPath: String = "m/44'/60'/0'/0"
//    public static var defaultPathPrefix: String = "m/44'/60'/0'"
//    public static var defaultPathMetamask: String = "m/44'/60'/0'/0/0"
//    public static var defaultPathMetamaskPrefix: String = "m/44'/60'/0'/0"
//    public static var hardenedIndexPrefix: UInt32 = (UInt32(1) << 31)
//}
//
//extension Bip32 {
//    public func derive (index: UInt32, derivePrivateKey:Bool, hardened: Bool = false) -> Bip32? {
//        if derivePrivateKey {
//            if self.hasPrivate { // derive private key when is itself extended private key
//                var entropy:Array<UInt8>
//                var trueIndex: UInt32
//                if index >= (UInt32(1) << 31) || hardened {
//                    trueIndex = index;
//                    if trueIndex < (UInt32(1) << 31) {
//                        trueIndex = trueIndex + (UInt32(1) << 31)
//                    }
//                    let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
//                    var inputForHMAC = Data()
//                    inputForHMAC.append(Data([UInt8(0x00)]))
//                    inputForHMAC.append(self.privateKey!)
//                    inputForHMAC.append(trueIndex.serialize32())
//                    guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
//                    guard ent.count == 64 else { return nil }
//                    entropy = ent
//                } else {
//                    trueIndex = index
//                    let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
//                    var inputForHMAC = Data()
//                    inputForHMAC.append(self.publicKey)
//                    inputForHMAC.append(trueIndex.serialize32())
//                    guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
//                    guard ent.count == 64 else { return nil }
//                    entropy = ent
//                }
//                let I_L = entropy[0..<32]
//                let I_R = entropy[32..<64]
//                let cc = Data(I_R)
//                let bn = BigUInt(Data(I_L))
//                if bn > HDNode.curveOrder {
//                    if trueIndex < UInt32.max {
//                        return self.derive(index:index+1, derivePrivateKey: derivePrivateKey, hardened:hardened)
//                    }
//                    return nil
//                }
//                let newPK = (bn + BigUInt(self.privateKey!)) % HDNode.curveOrder
//                if newPK == BigUInt(0) {
//                    if trueIndex < UInt32.max {
//                        return self.derive(index:index+1, derivePrivateKey: derivePrivateKey, hardened:hardened)
//                    }
//                    return nil
//                }
//                guard let privKeyCandidate = newPK.serialize().setLengthLeft(32) else {return nil}
//                guard SECP256K1.verifyPrivateKey(privateKey: privKeyCandidate) else {return nil }
//                guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: privKeyCandidate, compressed: true) else {return nil}
//                guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else {return nil}
//                guard self.depth < UInt8.max else {return nil}
//                let newNode = HDNode()
//                newNode.chaincode = cc
//                newNode.depth = self.depth + 1
//                newNode.publicKey = pubKeyCandidate
//                newNode.privateKey = privKeyCandidate
//                newNode.childNumber = trueIndex
//                guard let fprint = try? RIPEMD160.hash(message: self.publicKey.sha256())[0..<4] else {
//                    return nil
//                }
//                newNode.parentFingerprint = fprint
//                var newPath = String()
//                if newNode.isHardened {
//                    newPath = self.path! + "/"
//                    newPath += String(newNode.index % HDNode.hardenedIndexPrefix) + "'"
//                } else {
//                    newPath = self.path! + "/" + String(newNode.index)
//                }
//                newNode.path = newPath
//                return newNode
//            } else {
//                return nil // derive private key when is itself extended public key (impossible)
//            }
//        }
//        else { // deriving only the public key
//            var entropy:Array<UInt8> // derive public key when is itself public key
//            if index >= (UInt32(1) << 31) || hardened {
//                return nil // no derivation of hardened public key from extended public key
//            } else {
//                let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
//                var inputForHMAC = Data()
//                inputForHMAC.append(self.publicKey)
//                inputForHMAC.append(index.serialize32())
//                guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
//                guard ent.count == 64 else { return nil }
//                entropy = ent
//            }
//            let I_L = entropy[0..<32]
//            let I_R = entropy[32..<64]
//            let cc = Data(I_R)
//            let bn = BigUInt(Data(I_L))
//            if bn > HDNode.curveOrder {
//                if index < UInt32.max {
//                    return self.derive(index:index+1, derivePrivateKey: derivePrivateKey, hardened:hardened)
//                }
//                return nil
//            }
//            guard let tempKey = bn.serialize().setLengthLeft(32) else {return nil}
//            guard SECP256K1.verifyPrivateKey(privateKey: tempKey) else {return nil }
//            guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: tempKey, compressed: true) else {return nil}
//            guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else {return nil}
//            guard let newPublicKey = SECP256K1.combineSerializedPublicKeys(keys: [self.publicKey, pubKeyCandidate], outputCompressed: true) else {return nil}
//            guard newPublicKey.bytes[0] == 0x02 || newPublicKey.bytes[0] == 0x03 else {return nil}
//            guard self.depth < UInt8.max else {return nil}
//            let newNode = HDNode()
//            newNode.chaincode = cc
//            newNode.depth = self.depth + 1
//            newNode.publicKey = pubKeyCandidate
//            newNode.childNumber = index
//            guard let fprint = try? RIPEMD160.hash(message: self.publicKey.sha256())[0..<4] else {
//                return nil
//            }
//            newNode.parentFingerprint = fprint
//            var newPath = String()
//            if newNode.isHardened {
//                newPath = self.path! + "/"
//                newPath += String(newNode.index % HDNode.hardenedIndexPrefix) + "'"
//            } else {
//                newPath = self.path! + "/" + String(newNode.index)
//            }
//            newNode.path = newPath
//            return newNode
//        }
//    }
//
//    public func derive (path: String, derivePrivateKey: Bool = true) -> Bip32? {
//        let components = path.components(separatedBy: "/")
//        var currentNode: Bip32 = self
//        var firstComponent = 0
//        if path.hasPrefix("m") {
//            firstComponent = 1
//        }
//        for component in components[firstComponent ..< components.count] {
//            var hardened = false
//            if component.hasSuffix("'") {
//                hardened = true
//            }
//            guard let index = UInt32(component.trimmingCharacters(in: CharacterSet(charactersIn: "'"))) else {return nil}
//            guard let newNode = currentNode.derive(index: index, derivePrivateKey: derivePrivateKey, hardened: hardened) else {return nil}
//            currentNode = newNode
//        }
//        return currentNode
//    }
//
//    public func serializeToString(serializePublic: Bool = true, version: HDversion = HDversion()) -> String? {
//        guard let data = self.serialize(serializePublic: serializePublic, version: version) else { return nil }
//        let encoded = Base58.encode(data)
//        return encoded
//    }
//
//    public func serialize(serializePublic: Bool = true, version: HDversion = HDversion()) -> Data? {
//        var data = Data()
//        if (!serializePublic && !self.hasPrivate) {return nil}
//        if serializePublic {
//            data.append(version.publicPrefix)
//        } else {
//            data.append(version.privatePrefix)
//        }
//        data.append(contentsOf: [self.depth])
//        data.append(self.parentFingerprint)
//        data.append(self.childNumber.serialize32())
//        data.append(self.chaincode)
//        if serializePublic {
//            data.append(self.publicKey)
//        } else {
//            data.append(contentsOf: [0x00])
//            data.append(self.privateKey!)
//        }
//        let hashedData = data.sha256().sha256()
//        let checksum = hashedData[0..<4]
//        data.append(checksum)
//        return data
//    }
//
//}
//


public extension Data {
    /// Sets data.count to toBytes and fills missing bytes at the start of the data
    /// - Parameter toBytes: Desired data size
    /// - Parameter isNegative: Fills with ff if negative. default: false
    /// - Returns: Data with desired size
    func setLengthLeft(_ toBytes: UInt64, isNegative: Bool = false) -> Data? {
        let existingLength = UInt64(count)
        if existingLength == toBytes {
            return Data(self)
        } else if existingLength > toBytes {
            return nil
        }
        var data: Data
        if isNegative {
            data = Data(repeating: UInt8(255), count: Int(toBytes - existingLength))
        } else {
            data = Data(repeating: UInt8(0), count: Int(toBytes - existingLength))
        }
        data.append(self)
        return data
    }

    /// Sets data.count to toBytes and fills missing bytes at the end of the data
    /// - Parameter toBytes: Desired data size
    /// - Parameter isNegative: Fills with ff if negative. default: false
    /// - Returns: Data with desired size
    func setLengthRight(_ toBytes: UInt64, isNegative: Bool = false) -> Data? {
        let existingLength = UInt64(count)
        if existingLength == toBytes {
            return Data(self)
        } else if existingLength > toBytes {
            return nil
        }
        var data: Data = Data()
        data.append(self)
        if isNegative {
            data.append(Data(repeating: UInt8(255), count: Int(toBytes - existingLength)))
        } else {
            data.append(Data(repeating: UInt8(0), count: Int(toBytes - existingLength)))
        }
        return data
    }
}

class _HDKey {
    private(set) var privateKey: Data?
    private(set) var publicKey: Data
    private(set) var chainCode: Data
    private(set) var depth: UInt8
    private(set) var fingerprint: Data
    private(set) var childIndex: UInt32

    init(privateKey: Data?, publicKey: Data, chainCode: Data, depth: UInt8, fingerprint: Data, childIndex: UInt32) {
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
        let digest = Crypto.HMACSHA512(key: chainCode, data: data)
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

        let fingerPrint = RIPEMD160.hash(publicKey)//.to(type: UInt32.self)
        return _HDKey(privateKey: result, publicKey: result, chainCode: Data(derivedChainCode), depth: self.depth + 1, fingerprint: fingerPrint, childIndex: childIndex)
    }
}

class _SwiftKey {
    public static func computePublicKey(fromPrivateKey privateKey: Data, compression: Bool) -> Data {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
            return Data()
        }
        defer { secp256k1_context_destroy(ctx) }
        var pubkey = secp256k1_pubkey()
        var seckey: [UInt8] = privateKey.map { $0 }
        if seckey.count != 32 {
            return Data()
        }
        if secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey) == 0 {
            return Data()
        }
        if compression {
            var serializedPubkey = [UInt8](repeating: 0, count: 33)
            var outputlen = 33
            if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 0 {
                return Data()
            }
            if outputlen != 33 {
                return Data()
            }
            return Data(serializedPubkey)
        } else {
            var serializedPubkey = [UInt8](repeating: 0, count: 65)
            var outputlen = 65
            if secp256k1_ec_pubkey_serialize(ctx, &serializedPubkey, &outputlen, &pubkey, UInt32(SECP256K1_EC_UNCOMPRESSED)) == 0 {
                return Data()
            }
            if outputlen != 65 {
                return Data()
            }
            return Data(serializedPubkey)
        }
    }
}
