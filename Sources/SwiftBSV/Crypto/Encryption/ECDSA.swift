//
//  ECDSA.swift
//  ECDSA
//
//  Created by yuzushioh on 2018/01/25.
//  Copyright © 2018 yuzushioh. All rights reserved.
//

import Foundation
import secp256k1

public final class ECDSA {
//    public static let secp256k1 = ECDSA()
//    
    public static func sign(_ data: Data, privateKey: Data) -> Data {
        precondition(data.count == 32, "Hash must be 32 bytes size")

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }

        data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            guard let dataPointer = ptr.bindMemory(to: UInt8.self).baseAddress else { return }
            privateKey.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) in
                guard let privateKeyPointer = pkPtr.bindMemory(to: UInt8.self).baseAddress else { return }
                secp256k1_ecdsa_sign(ctx, signature, dataPointer, privateKeyPointer, secp256k1_nonce_function_rfc6979, nil)
            }
        }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate() }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length = 64
        var compactSig = Data(count: length)

        compactSig.withUnsafeMutableBytes { (ptr) -> Void in
            guard let pointer = ptr.bindMemory(to: UInt8.self).baseAddress else { return }
            secp256k1_ecdsa_signature_serialize_compact(ctx, pointer, normalizedsig)
        }

        return compactSig

//        let compactSig = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
//
//
//        var length: size_t = 128
//        var der = Data(count: length)
//        der.withUnsafeMutableBytes({ (ptr: UnsafeMutableRawBufferPointer) -> Void in
//            guard let pointer = ptr.bindMemory(to: UInt8.self).baseAddress else { return }
//            secp256k1_ecdsa_signature_serialize_der(ctx, pointer, &length, signature)
//        })
//        der.count = length
//
//        return der
    }

    public static func signMessage(_ data: Data, withPrivateKey privateKey: Data) throws -> Data {
        precondition(data.count == 32, "Hash must be 32 bytes size")
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }
        let status = data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            privateKey.withUnsafeBytes {
                secp256k1_ecdsa_sign(
                    ctx,
                    signature,
                    ptr.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                    $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                    nil,
                    nil
                )
            }
        }
        guard status == 1 else { fatalError() }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate() }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({
            return secp256k1_ecdsa_signature_serialize_der(
                ctx,
                $0.bindMemory(to: UInt8.self).baseAddress.unsafelyUnwrapped,
                &length,
                normalizedsig
            ) }) == 1 else { fatalError() }
        der.count = length

        return der
    }

    static public func verifySignature(_ sigData: Data, message: Data, publicKeyData: Data) throws -> Bool {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else { return false }
        var pubkey = secp256k1_pubkey()
        var signature = secp256k1_ecdsa_signature()
        secp256k1_ecdsa_signature_parse_der(ctx, &signature, sigData.bytes, sigData.count)
        
        if (secp256k1_ec_pubkey_parse(ctx, &pubkey, publicKeyData.bytes, publicKeyData.count) != 1) {
            return false
        };
        
        if (secp256k1_ecdsa_verify(ctx, &signature, message.bytes, &pubkey) != 1) {
            return false
        };
        secp256k1_context_destroy(ctx);
        return true
    }

    static public func verifySignatureCompact(_ sigData: Data, message: Data, publicKeyData: Data) throws -> Bool {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else { return false }
        var pubkey = secp256k1_pubkey()
        var signature = secp256k1_ecdsa_signature()
        secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sigData.bytes)

        if (secp256k1_ec_pubkey_parse(ctx, &pubkey, publicKeyData.bytes, publicKeyData.count) != 1) {
            return false
        };

        if (secp256k1_ecdsa_verify(ctx, &signature, message.bytes, &pubkey) != 1) {
            return false
        };
        secp256k1_context_destroy(ctx);
        return true
    }
}


public struct Secp256k1 {
    public typealias PrivateKey = [UInt8]
    public typealias PublicKey = [UInt8]
    public typealias Signature = [UInt8]
    public typealias RecoveryID = Int32

    public enum Error: Swift.Error {
        case invalidPublicKey
        case invalidPrivateKey
        case invalidSignature
        case invalidRecoveryID
        case internalError
    }

    public enum NonceFunction: String {
        case `default` = "default"
        case rfc6979 = "nonce_function_rfc6979"

        var function: secp256k1_nonce_function {
            switch self {
            case .default:
                return secp256k1_nonce_function_default
            case .rfc6979:
                return secp256k1_nonce_function_rfc6979
            }
        }
    }

    public enum Compression {
        case uncompressed
        case compressed

        var flag: UInt32 {
            switch self {
            case .uncompressed:
                return UInt32(SECP256K1_EC_UNCOMPRESSED)
            case .compressed:
                return UInt32(SECP256K1_EC_COMPRESSED)
            }
        }

        var pubkeyLength: Int {
            switch self {
            case .uncompressed:
                return 65
            case .compressed:
                return 33
            }
        }
    }

    public static func keyPair() throws -> (PrivateKey, PublicKey) {
        var privkey = PrivateKey(repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, privkey.count, &privkey)
        guard status == errSecSuccess,
            let pubkey = try? derivePublicKey(for: privkey) else {
            throw Error.internalError
        }

        return (privkey, pubkey)
    }

    public static func derivePublicKey(for privkey: PrivateKey, with compression: Compression = .uncompressed) throws -> PublicKey {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cPubkey = secp256k1_pubkey()
        var pubkeyLen = compression.pubkeyLength
        var pubkey = PublicKey(repeating: 0, count: pubkeyLen)

        guard secp256k1_context_randomize(context, privkey) == 1,
            secp256k1_ec_pubkey_create(context, &cPubkey, privkey) == 1,
            secp256k1_ec_pubkey_serialize(context, &pubkey, &pubkeyLen, &cPubkey, compression.flag) == 1 else {
            throw Error.internalError
        }

        return pubkey
    }

    public static func compressPublicKey(_ pubkey: PublicKey) throws -> PublicKey {
        guard pubkey.count == 65,
            let firstByte = pubkey.first,
            firstByte == 4 else {
            throw Error.invalidPublicKey
        }

        let x = Array(pubkey[1 ... 32])
        let yLastByte = pubkey.last!
        return yLastByte & 1 == 1 ? ([3] + x) : ([2] + x)
    }

    public static func decompressPublicKey(_ pubkey: PublicKey) throws -> PublicKey {
        guard pubkey.count == 33,
            let firstByte = pubkey.first,
            firstByte == 2 || firstByte == 3 else {
            throw Error.invalidPublicKey
        }

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cPubkey = secp256k1_pubkey()
        var uncompressedKeyLen = 65
        var uncompressedPubkey = [UInt8](repeating: 0, count: uncompressedKeyLen)
        guard secp256k1_ec_pubkey_parse(context, &cPubkey, pubkey, pubkey.count) == 1,
            secp256k1_ec_pubkey_serialize(context, &uncompressedPubkey, &uncompressedKeyLen, &cPubkey, Compression.uncompressed.flag) == 1 else {
            throw Error.internalError
        }

        return uncompressedPubkey
    }

    public static func privateKeyTweakAdd(_ privkey: PrivateKey, tweak: [UInt8]) throws -> [UInt8] {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var tweaked = privkey
        guard secp256k1_ec_privkey_tweak_add(context, &tweaked, tweak) == 1 else {
            throw Error.internalError
        }

        return tweaked
    }

    public static func privateKeyTweakMul(_ privkey: PrivateKey, tweak: [UInt8]) throws -> [UInt8] {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var tweaked = privkey
        guard secp256k1_ec_privkey_tweak_mul(context, &tweaked, tweak) == 1 else {
            throw Error.internalError
        }
        return tweaked
    }

    public static func publicKeyTweakAdd(_ pubkey: PublicKey, tweak: [UInt8]) throws -> [UInt8] {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cPubkey = secp256k1_pubkey()
        let flag = try compression(of: pubkey).flag
        var outputLen = pubkey.count
        var tweaked = [UInt8](repeating: 0, count: outputLen)

        guard secp256k1_ec_pubkey_parse(context, &cPubkey, pubkey, pubkey.count) == 1,
            secp256k1_ec_pubkey_tweak_add(context, &cPubkey, tweak) == 1,
            secp256k1_ec_pubkey_serialize(context, &tweaked, &outputLen, &cPubkey, flag) == 1 else {
            throw Error.internalError
        }

        return Array(tweaked[..<outputLen])
    }

    public static func publicKeyTweakMul(_ pubkey: PublicKey, tweak: [UInt8]) throws -> [UInt8] {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cPubkey = secp256k1_pubkey()
        let flag = try compression(of: pubkey).flag
        var outputLen = pubkey.count
        var tweaked = [UInt8](repeating: 0, count: outputLen)

        guard secp256k1_ec_pubkey_parse(context, &cPubkey, pubkey, pubkey.count) == 1,
            secp256k1_ec_pubkey_tweak_mul(context, &cPubkey, tweak) == 1,
            secp256k1_ec_pubkey_serialize(context, &tweaked, &outputLen, &cPubkey, flag) == 1 else {
            throw Error.internalError
        }

        return Array(tweaked[..<outputLen])
    }

    public static func sign(msg: [UInt8], with privkey: PrivateKey, nonceFunction: NonceFunction) throws -> Signature {
        guard isValidPrivateKey(privkey) else {
            throw Error.invalidPrivateKey
        }

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cSignature = secp256k1_ecdsa_signature()

        guard secp256k1_ecdsa_sign(context, &cSignature, msg, privkey, nonceFunction.function, nil) == 1 else {
            throw Error.internalError
        }

        var sigLen = 74
        var signature = [UInt8](repeating: 0, count: sigLen)

        guard secp256k1_ecdsa_signature_serialize_der(context, &signature, &sigLen, &cSignature) == 1,
            secp256k1_ecdsa_signature_parse_der(context, &cSignature, &signature, sigLen) == 1 else {
            throw Error.internalError
        }

        return Array(signature[..<sigLen])
    }

    public static func verify(msg: [UInt8], sig: Signature, pubkey: PublicKey) -> Bool {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cSignature = secp256k1_ecdsa_signature()
        var cPubkey = secp256k1_pubkey()

        guard secp256k1_ecdsa_signature_parse_der(context, &cSignature, sig, sig.count) == 1,
            secp256k1_ec_pubkey_parse(context, &cPubkey, pubkey, pubkey.count) == 1 else {
            return false
        }

        if secp256k1_ecdsa_verify(context, &cSignature, msg, &cPubkey) != 1 {
            return false
        }
        return true
    }

    public static func signCompact(msg: [UInt8], with privkey: PrivateKey, nonceFunction: NonceFunction) throws -> (sig: Signature, recID: RecoveryID) {
        guard isValidPrivateKey(privkey) else {
            throw Error.invalidPrivateKey
        }

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cSignature = secp256k1_ecdsa_recoverable_signature()
        guard secp256k1_ecdsa_sign_recoverable(context, &cSignature, msg, privkey, nonceFunction.function, nil) == 1 else {
            throw Error.internalError
        }

        var signature = [UInt8](repeating: 0, count: 64)
        var recoveryID: RecoveryID = 0
        guard secp256k1_ecdsa_recoverable_signature_serialize_compact(context, &signature, &recoveryID, &cSignature) == 1 else {
            throw Error.internalError
        }

        return (signature, recoveryID)
    }

    public static func verifyCompact(msg: [UInt8], sig: Signature, pubkey: PublicKey) -> Bool {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cSignature = secp256k1_ecdsa_signature()
        var cPubkey = secp256k1_pubkey()

        guard secp256k1_ecdsa_signature_parse_compact(context, &cSignature, sig) == 1,
            secp256k1_ec_pubkey_parse(context, &cPubkey, pubkey, pubkey.count) == 1 else {
            return false
        }

        if secp256k1_ecdsa_verify(context, &cSignature, msg, &cPubkey) != 1 {
            return false
        }

        return true
    }

    public static func recoverCompact(msg: [UInt8], sig: Signature, recID: RecoveryID, compression: Compression) throws -> PublicKey {
        guard isValidRecoveryID(recID) else {
            throw Error.invalidRecoveryID
        }

        guard isValidCompactSignature(sig) else {
            throw Error.invalidSignature
        }

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cSignature = secp256k1_ecdsa_recoverable_signature()
        var cPubkey = secp256k1_pubkey()
        var pubkeyLen = compression.pubkeyLength
        var pubkey = [UInt8](repeating: 0, count: pubkeyLen)

        guard secp256k1_ecdsa_recoverable_signature_parse_compact(context, &cSignature, sig, recID) == 1,
            secp256k1_ecdsa_recover(context, &cPubkey, &cSignature, msg) == 1,
            secp256k1_ec_pubkey_serialize(context, &pubkey,
                                          &pubkeyLen, &cPubkey, compression.flag) == 1 else {
            throw Error.internalError
        }

        return pubkey
    }

    public static func compression(of pubkey: PublicKey) throws -> Compression {
        if pubkey.count == 65, pubkey.first! == 4 {
            return .uncompressed
        } else if pubkey.count == 33, pubkey.first! == 2 || pubkey.first! == 3 {
            return .compressed
        } else {
            throw Error.invalidPublicKey
        }
    }

    public static func isValidPublicKey(_ pubkey: PublicKey) -> Bool {
        guard (pubkey.count == 33 && (pubkey.first! == 2 || pubkey.first! == 3)) ||
            (pubkey.count == 65 && pubkey.first! == 4) else {
            return false
        }

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var cPubkey = secp256k1_pubkey()
        return secp256k1_ec_pubkey_parse(context, &cPubkey, pubkey, pubkey.count) == 1
    }

    public static func isValidPrivateKey(_ privkey: PrivateKey) -> Bool {
        guard privkey.count == 32 else {
            return false
        }

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        return secp256k1_ec_seckey_verify(context, privkey) == 1
    }

    private static func isValidRecoveryID(_ recID: RecoveryID) -> Bool {
        return recID >= 0 && recID <= 3
    }

    private static func isValidCompactSignature(_ sig: Signature) -> Bool {
        return sig.count == 64
    }
}
