//
//  Crypto.swift
//  Swift BSV
//
//  Created by yuzushioh on 2018/02/06.
//  Modifications by Will Townsend from 2020/10/19
//
//  Copyright © 2018 yuzushioh. All rights reserved.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import CryptoSwift
import secp256k1

public final class Crypto {

    public static func ripemd160(_ data: Data) -> Data {
        return RIPEMD160.hash(data)
    }

    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(data.sha256())
    }

   public static func hmacsha512(key: Data, data: Data) -> Data {
        let output: [UInt8]
        do {
            output = try HMAC(key: key.bytes, variant: .sha512).authenticate(data.bytes)
        } catch let error {
            fatalError("Error occured. Description: \(error.localizedDescription)")
        }
        return Data(output)
    }

//    public static func PBKDF2SHA512(password: [UInt8], salt: [UInt8]) -> Data {
//        let output: [UInt8]
//        do {
//            output = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 2048, variant: .sha512).calculate()
//        } catch let error {
//            fatalError("PKCS5.PBKDF2 faild: \(error.localizedDescription)")
//        }
//        return Data(output)
//    }

//    public static func sha3keccak256(data:Data) -> Data {
//        return Data(SHA3(variant: .keccak256).calculate(for: data.bytes))
//    }
//
//    public static func hashSHA3_256(_ data: Data) -> Data {
//        return Data(CryptoSwift.SHA3(variant: .sha256).calculate(for: data.bytes))
//    }
//
//    public static func sign(_ hash: Data, privateKey: Data) throws -> Data {
//        let encrypter = EllipticCurveEncrypterSecp256k1()
//        guard var signatureInInternalFormat = encrypter.sign(hash: hash, privateKey: privateKey) else {
//            throw HDWalletKitError.failedToSign
//        }
//        return encrypter.export(signature: &signatureInInternalFormat)
//    }

    public static func computePublicKey(fromPrivateKey privateKey: Data, compressed: Bool) -> Data {
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
        if compressed {
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

    /// Serialize a publicKey
    ///
    /// Useful to convert a compressed pubKey into an uncompressed pubKey
    public static func serializePublicKey(from publicKey: Data, compressed: Bool = true) -> Data {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else {
            return Data()
        }
        defer { secp256k1_context_destroy(ctx) }
        var pubkey = secp256k1_pubkey()
        var input: [UInt8] = publicKey.map { $0 }

        if secp256k1_ec_pubkey_parse(ctx, &pubkey, &input, input.count) == 0 {
            return Data()
        }

        if compressed {
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

