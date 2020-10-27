//
//  BitcoinSignedMessage.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-23.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
/**
 * Bitcoin Signed Message
 * ======================
 *
 * "Bitcoin Signed Message" just refers to a standard way of signing and
 * verifying an arbitrary message. The standard way to do this involves using a
 * "Bitcoin Signed Message:\n" prefix, which this code does. You are probably
 * interested in the static Bsm.sign( ... ) and Bsm.verify( ... ) functions,
 * which deal with a base64 string representing the compressed format of a
 * signature.
 */
struct BitcoinSignedMessage {


    /// Sign the message with the private key
    /// - Parameters:
    ///   - message: the message you'd like to sign
    ///   - privateKey: the private key to sign with
    /// - Returns: A string containing the signed signature
    static func sign(message: String, privateKey: PrivateKey) -> String {
        let messageData = message.data(using: .utf8)!
        let hashBuf = magicHash(message: messageData)
        let (sig, recoveryId) = Crypto.signCompact(hashBuf, privateKey: privateKey)

        // BSV.js calculates the full public key here

        var value = recoveryId + 27 + 4

        let isCompressed = true
        if isCompressed == false {
            value = value - 4
        }

        var sigData = Data()
        sigData += UInt8(value)
        sigData += sig

        return sigData.base64EncodedString()
    }

    static func verify(message: String, signature: String, address: Address) -> Bool {
        let messageData = message.data(using: .utf8)!
        let hashBuf = magicHash(message: messageData)
        guard let sigBuffer = Data(base64Encoded: signature) else {
            return false
        }

        guard sigBuffer.count == 1 + 32 + 32 else {
            return false
        }

        let sig = sigBuffer.suffix(from: 1)

        // Sig From compact
        var isCompressed = true
        var recovery = sigBuffer[0] - 27 - 4

        if recovery < 0 {
            isCompressed = false
            recovery = recovery + 4
        }

        let publicKeyBytes = try! Secp256k1.recoverCompact(
            msg: hashBuf.bytes,
            sig: sig.bytes,
            recID: Secp256k1.RecoveryID(recovery),
            compression: Secp256k1.Compression.uncompressed
        )

        guard let publicKey = PublicKey(fromDer: Data(publicKeyBytes)) else {
            return false
        }

        let valid = Secp256k1.verifyCompact(msg: hashBuf.bytes, sig: sig.bytes, pubkey: publicKeyBytes)

        guard valid == true else {
            return false
        }

        guard address.hashBuffer == publicKey.address.hashBuffer else {
            return false
        }

        return true
    }

    private static func magicHash(message: Data) -> Data {
        var data = Data()
        data += VarInt(MagicBytes.count).data
        data += MagicBytes
        data += VarInt(message.count).data
        data += message

        let hash = Crypto.sha256sha256(data)
        return hash
    }

    private static let MagicBytes = "Bitcoin Signed Message:\n".data(using: .utf8)!
}
