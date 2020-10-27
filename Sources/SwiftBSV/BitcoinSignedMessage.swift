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

        var signature = Signature(fromRsBuffer: sig)
        signature?.recovery = Int(recoveryId)

        return signature!.toBuffer().base64EncodedString()
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

        guard let signature = Signature(fromCompact: sigBuffer) else {
            return false
        }

        var sig = Data()
        sig += signature.r
        sig += signature.s

        let publicKeyBytes = try! Secp256k1.recoverCompact(
            msg: hashBuf.bytes,
            sig: sig.bytes,
            recID: Secp256k1.RecoveryID(signature.recovery!),
            compression: signature.isCompressed! ? .compressed : .uncompressed
        )

        guard let publicKey = PublicKey(fromDer: Data(publicKeyBytes)) else {
            return false
        }

        guard Secp256k1.verifyCompact(
            msg: hashBuf.bytes,
            sig: sig.bytes,
            pubkey: publicKeyBytes
        ) == true else {
            return false
        }

        // Not sure if we need to do this, but when writing this, there were a few cases where the address would be incorrect due to the difference in public key compression.
        var otherPublicKey = publicKey
        otherPublicKey.isCompressed.toggle()

        guard address.hashBuffer == publicKey.address.hashBuffer || address.hashBuffer == otherPublicKey.address.hashBuffer else {
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
