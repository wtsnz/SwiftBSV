//
//  Transaction.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
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

import Foundation

/// tx describes a bitcoin transaction, in reply to getdata
public struct Transaction {
    /// Transaction data format version (note, this is signed)
    public var version: UInt32
    /// If present, always 0001, and indicates the presence of witness data
    // public let flag: UInt16 // If present, always 0001, and indicates the presence of witness data
    /// Number of Transaction inputs (never zero)
    public var txInCount: VarInt {
        return VarInt(inputs.count)
    }
    /// A list of 1 or more transaction inputs or sources for coins
    public var inputs: [TransactionInput]
    /// Number of Transaction outputs
    public var txOutCount: VarInt {
        return VarInt(outputs.count)
    }
    /// A list of 1 or more transaction outputs or destinations for coins
    public var outputs: [TransactionOutput]
    /// A list of witnesses, one for each input; omitted if flag is omitted above
    // public let witnesses: [TransactionWitness] // A list of witnesses, one for each input; omitted if flag is omitted above
    /// The block number or timestamp at which this transaction is unlocked:
    public var lockTime: UInt32

    public var txHash: Data {
        return Crypto.sha256sha256(serialized())
    }

    public var txID: String {
        return Data(txHash.reversed()).hex
    }

    static var empty = Transaction(version: 1, inputs: [], outputs: [], lockTime: 0)

    public init(version: UInt32, inputs: [TransactionInput], outputs: [TransactionOutput], lockTime: UInt32) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }

    public func serialized() -> Data {
        var data = Data()
        data += version
        data += txInCount.serialized()
        data += inputs.flatMap { $0.serialized() }
        data += txOutCount.serialized()
        data += outputs.flatMap { $0.serialized() }
        data += lockTime
        return data
    }

    public func isCoinbase() -> Bool {
        return inputs.count == 1 && inputs[0].isCoinbase()
    }

    public static func deserialize(_ data: Data) -> Transaction {
        let byteStream = ByteStream(data)
        return deserialize(byteStream)
    }

    static func deserialize(_ byteStream: ByteStream) -> Transaction {
        let version = byteStream.read(UInt32.self)
        let txInCount = byteStream.read(VarInt.self)
        var inputs = [TransactionInput]()
        for _ in 0..<Int(txInCount.underlyingValue) {
            inputs.append(TransactionInput.deserialize(byteStream))
        }
        let txOutCount = byteStream.read(VarInt.self)
        var outputs = [TransactionOutput]()
        for _ in 0..<Int(txOutCount.underlyingValue) {
            outputs.append(TransactionOutput.deserialize(byteStream))
        }
        let lockTime = byteStream.read(UInt32.self)
        return Transaction(version: version, inputs: inputs, outputs: outputs, lockTime: lockTime)
    }
}

// MARK: - Transaction + TxBuilder

extension Transaction {

    @discardableResult
    mutating func addTransactionInput(_ input: TransactionInput) -> Self {
        inputs.append(input)
        return self
    }

    @discardableResult
    mutating func addTransactionInput(txHashBuffer: Data, txOutNum: UInt32, script: Script, nSequence: UInt32) -> Self {

        let transactionInput = TransactionInput(
            previousOutput: TransactionOutPoint(
                hash: txHashBuffer,
                index: txOutNum
            ),
            signatureScript: script.data,
            sequence: nSequence
        )

        inputs.append(transactionInput)
        return self
    }

    @discardableResult
    mutating func addTransactionOutput(_ output: TransactionOutput) -> Self {
        outputs.append(output)
        return self
    }

    @discardableResult
    mutating func addTransactionOutput(value: UInt64, lockingScript: Script) -> Self {
        let output = TransactionOutput(value: value, lockingScript: lockingScript.data)
        outputs.append(output)
        return self
    }

    mutating func removeLastTransactionOutput() -> TransactionOutput? {
        return outputs.popLast()
    }

    mutating func setVersion(_ version: UInt32) {
        self.version = version
    }

    mutating func setLockTime(_ nLockTime: UInt32) {
        self.lockTime = nLockTime
    }

    /// BIP 69 sorting. Be sure to sign after sorting.
    mutating func sort() {
        // TODO
//        inputs.sort(by: { first, second in
//            return first.previousOutput.hash.reversed() > second.previousOutput.hash.reversed()
//        })
    }

    mutating func fillSig(nIn: Int, nScriptChunk: Int, sig: Data, sigHashType: SighashType, publicKey: PublicKey) {

        
        var inputs = self.inputs
        let input = inputs[nIn]

        // Create unlocking script

        let script = Script(data: input.signatureScript)!

        let sigWithType = sig + [sigHashType.rawValue]
        let unlockingScript = try! Script()
            .appendData(sigWithType)
            .appendData(publicKey.toDer())

        
//        var chunks = script.scriptChunks
//        chunks[nScriptChunk] = unlockingScript.chunk(at: 0)

//        let filledScript = Script(chunks: chunks)

        let unlockedTransactionInput = TransactionInput(
            previousOutput: input.previousOutput,
            signatureScript: unlockingScript.data,
            sequence: input.sequence
        )

        inputs[nIn] = unlockedTransactionInput
        self.inputs = inputs
    }

}

// MARK: - Transaction + SigHash

extension Transaction {

    // https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md
    private func hashPrevouts() -> Data {
        var data = Data()
        for txIn in inputs {
            data += txIn.previousOutput.hash
            data += txIn.previousOutput.index
        }
        return Crypto.sha256sha256(data)
    }

    private func hashSequence() -> Data {
        var data = Data()
        for txIn in inputs {
            data += txIn.sequence
        }
        return Crypto.sha256sha256(data)
    }

    private func hashOutputs() -> Data {
        var data = Data()
        for txOut in outputs {
            data += txOut.serialized()
        }
        return Crypto.sha256sha256(data)
    }

    func sighash(nHashType: SighashType, nIn: Int, subScript: Script, value: UInt64, flags: TransactionSigHashFlags = .none) -> Data {

        // start with UAHF part (Bitcoin SV)
        // https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md
        if nHashType.hasForkId && flags.contains(.scriptEnableSighashForkId) {
            return Transaction.bip143_sighash(tx: self, nHashType: nHashType, nIn: nIn, subScript: subScript, value: value)
        }

        return Transaction.legacySigHash(tx: self, nHashType: nHashType, nIn: nIn, subScript: subScript)
    }

    /// Generates a transaction digest for signing using BIP-143
    ///
    /// This is to be used for all tranasctions after the August 2017 fork.
    /// It fixing quadratic hashing and includes the amount spent in the hash.
    private static func bip143_sighash(tx: Transaction, nHashType: SighashType, nIn: Int, subScript: Script, value: UInt64) -> Data {
        var hashPrevouts = Data(repeating: 0, count: 32)
        var hashSequence = Data(repeating: 0, count: 32)
        var hashOutputs = Data(repeating: 0, count: 32)

        if !nHashType.isAnyoneCanPay {
            hashPrevouts = tx.hashPrevouts()
        }

        if !nHashType.isAnyoneCanPay && (nHashType.rawValue & 0x1f != BSVSighashType.SINGLE.rawValue) && (nHashType.rawValue & 0x1f != BSVSighashType.NONE.rawValue) {
            hashSequence = tx.hashSequence()
        }

        if (nHashType.rawValue & 0x1f != BSVSighashType.SINGLE.rawValue) && (nHashType.rawValue & 0x1f != BSVSighashType.NONE.rawValue) {
            hashOutputs = tx.hashOutputs()
        } else if (nHashType.rawValue & 0x1f == BSVSighashType.SINGLE.rawValue) && nIn < tx.outputs.count {
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
        data += nHashType.uint32

        let hash = Crypto.sha256sha256(data).reversed()
        return Data(hash)
    }

    /// Generates the transaction digest for signing using the legacy algorithm
    ///
    /// This is used for all transaction validation before the August 2017 fork.
    private static func legacySigHash(tx: Transaction, nHashType: SighashType, nIn: Int, subScript: Script) -> Data {
        var txCopy = tx

        // Remove all OP_CODESEPARATOR from the subScript
        var subScript = Script(chunks: subScript.scriptChunks)
        try! subScript.deleteOccurrences(of: OpCode.OP_CODESEPARATOR)

        var blankInputs = txCopy.inputs.map({ TransactionInput(previousOutput: $0.previousOutput, signatureScript: Script().data, sequence: $0.sequence) })

        blankInputs[nIn] = TransactionInput(previousOutput: blankInputs[nIn].previousOutput, signatureScript: subScript.data, sequence: blankInputs[nIn].sequence)

        txCopy.inputs = blankInputs


        if nHashType.isNone {
            txCopy.outputs = []

            // TODO Check tat this var modifies the array, not just the local var
            for (index, var input) in txCopy.inputs.enumerated() {
                if index != nIn {
                    input.sequence = 0
                }
            }
        } else if nHashType.isSingle {
            // The SIGHASH_SINGLE bug.
            // https://bitcointalk.org/index.php?topic=260595.0
            if nIn > txCopy.outputs.count - 1 {
                return Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")
            }

            var outputs = txCopy.outputs
            // TODO Check tat this var modifies the array, not just the local var
            for (index, _) in outputs.enumerated() {
                if index < nIn {
                    outputs[index] = TransactionOutput(
                        value: .max,
                        lockingScript: Script().data
                    )
                }
            }

            // TODO Check tat this var modifies the array, not just the local var
            for (index, var input) in txCopy.inputs.enumerated() {
                if index != nIn {
                    input.sequence = 0
                }
            }

            txCopy.outputs = outputs

        }

        // else sighash all

        if nHashType.isAnyoneCanPay {
            txCopy.inputs = [txCopy.inputs[nIn]]
        }

        let data = txCopy.serialized()
        let hash = Data(Crypto.sha256sha256(data).reversed())

        return hash
    }

    /// Sign and return the signature
    func sign(privateKey: PrivateKey, nHashType: SighashType, nIn: Int, subScript: Script, value: UInt64, flags: TransactionSigHashFlags = .scriptEnableSighashForkId) -> Data {
        let hashBuf = sighash(nHashType: nHashType, nIn: nIn, subScript: subScript, value: value, flags: flags)
        let hashBufRev = Data(hashBuf.reversed())
        let sig = Crypto.sign(hashBufRev, privateKey: privateKey)

        return sig
    }

}


struct TransactionSigHashFlags: OptionSet {
    let rawValue: Int

    static let none = TransactionSigHashFlags(rawValue: 1 << 0)
    static let scriptEnableSighashForkId = TransactionSigHashFlags(rawValue: 1 << 16)

    static let all: TransactionSigHashFlags = [.none, .scriptEnableSighashForkId]
}
