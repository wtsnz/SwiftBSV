//
//  SigOperation.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-27.
//  Copyright © 2020 wtsnz. All rights reserved.
//


import Foundation

struct TransactionInputSigner {

    static func signatureHash(tx: Transaction, signatureVersion: SignatureVersion, sighashType: SighashType, nIn: Int, subScript: Script, value: UInt64) -> Data {

        if sighashType.hasForkId && signatureVersion == .forkId {
            return Self.sighash(tx: tx, nIn: nIn, subScript: subScript, value: value, sighashType: sighashType)
        }

        return Self.legacySighash2(tx: tx, nIn: nIn, subScript: subScript, sighashType: sighashType)
    }

    // https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md
    static private func hashPrevouts(_ tx: Transaction) -> Data {
        var data = Data()
        for txIn in tx.inputs {
            data += txIn.previousOutput.hash
            data += txIn.previousOutput.index
        }
        return Crypto.sha256sha256(data)
    }

    static private func hashSequence(_ tx: Transaction) -> Data {
        var data = Data()
        for txIn in tx.inputs {
            data += txIn.sequence
        }
        return Crypto.sha256sha256(data)
    }

    static private func hashOutputs(_ tx: Transaction) -> Data {
        var data = Data()
        for txOut in tx.outputs {
            data += txOut.serialized()
        }
        return Crypto.sha256sha256(data)
    }


    /// Generates a transaction digest for signing using BIP-143
    ///
    /// This is to be used for all tranasctions after the August 2017 fork.
    /// It fixing quadratic hashing and includes the amount spent in the hash.
    private static func sighash(tx: Transaction, nIn: Int, subScript: Script, value: UInt64, sighashType: SighashType) -> Data {
        var hashPrevouts = Data(repeating: 0, count: 32)
        var hashSequence = Data(repeating: 0, count: 32)
        var hashOutputs = Data(repeating: 0, count: 32)

        if sighashType.hasAnyoneCanPay == false {
            hashPrevouts = Self.hashPrevouts(tx)
        }

        if sighashType.baseType == .all && sighashType.hasAnyoneCanPay == false {
            hashSequence = Self.hashSequence(tx)
        }

        if sighashType.baseType == .all {
            hashOutputs = Self.hashOutputs(tx)
        } else if sighashType.baseType == .single && nIn < tx.outputs.count {
            hashOutputs = Crypto.sha256sha256(tx.outputs[nIn].serialized())
        }

        var data = Data()
        data += tx.version
        data += hashPrevouts
        data += hashSequence
        data += tx.inputs[nIn].previousOutput.hash
        data += tx.inputs[nIn].previousOutput.index
        data += VarInt(subScript.data.count).data
        data += subScript.data
        data += value
        data += tx.inputs[nIn].sequence
        data += hashOutputs
        data += tx.lockTime
        data += sighashType.sighash

        let hash = Crypto.sha256sha256(data).reversed()
        return Data(hash)
    }

    /// Generates the transaction digest for signing using the legacy algorithm
    ///
    /// This is used for all transaction validation before the August 2017 fork.
    private static func legacySighash2(tx: Transaction, nIn: Int, subScript: Script, sighashType: SighashType) -> Data {

        // This algorithm is based on this
        // https://github.com/paritytech/parity-bitcoin/blob/0a3e376c223bbcc6ff4ddfdcdfcf8182236072c4/script/src/sign.rs#L171

        if nIn >= tx.inputs.count {
            //  nIn out of range
            return Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")
        }

        // Check for invalid use of SIGHASH_SINGLE
        if sighashType.baseType == .single && nIn >= tx.outputs.count {
            //  nOut out of range
            return Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")
        }

        let scriptPubKey = try! Script(chunks: subScript.scriptChunks)
            .deleteOccurrences(of: OpCode.OP_CODESEPARATOR)

        let inputs: [TransactionInput] = {
            if sighashType.hasAnyoneCanPay {
                let input = tx.inputs[nIn]
                return [TransactionInput(
                    previousOutput: input.previousOutput,
                    signatureScript: scriptPubKey.data,
                    sequence: input.sequence
                )]
            } else {
                return tx
                    .inputs
                    .enumerated()
                    .map({ n, input in
                        TransactionInput(
                            previousOutput: input.previousOutput,
                            signatureScript: n == nIn ? scriptPubKey.data : Data(),
                            sequence: ((sighashType.baseType == .single || sighashType.baseType == .none) && (n != nIn)) ? 0 : input.sequence
                        )
                    })
            }
        }()

        let outputs: [TransactionOutput] = {
            if sighashType.baseType == .all {
                return tx.outputs
            } else if sighashType.baseType == .single {
                return tx
                    .outputs
                    .prefix(upTo: nIn + 1)
                    .enumerated()
                    .map { n, out in
                        if n < nIn {
                            return TransactionOutput.default
                        }
                        return out
                    }
            } else {
                return []
            }
        }()

        let tx = Transaction(
            version: tx.version,
            inputs: inputs,
            outputs: outputs,
            lockTime: tx.lockTime
        )

        var buffer = Data()
        buffer += tx.serialized()
        buffer += sighashType.sighash

        return Data(Crypto.sha256sha256(buffer).reversed())
    }

}
