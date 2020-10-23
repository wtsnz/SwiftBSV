//
//  TransactionInput.swift
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

public struct TransactionInput {
    /// The previous output transaction reference, as an OutPoint structure
    public let previousOutput: TransactionOutPoint
    /// The length of the signature script
    public var scriptLength: VarInt {
        return VarInt(signatureScript.count)
    }
    /// Computational Script for confirming transaction authorization
    public let signatureScript: Data
    /// Transaction version as defined by the sender. Intended for "replacement" of transactions when information is updated before inclusion into a block.
    public let sequence: UInt32

    public init(previousOutput: TransactionOutPoint, signatureScript: Data, sequence: UInt32) {
        self.previousOutput = previousOutput
        self.signatureScript = signatureScript
        self.sequence = sequence
    }

    public func isCoinbase() -> Bool {
        return previousOutput.hash == Data(count: 32)
            && previousOutput.index == 0xFFFF_FFFF
    }

    public func serialized() -> Data {
        var data = Data()
        data += previousOutput.serialized()
        data += scriptLength.serialized()
        data += signatureScript
        data += sequence
        return data
    }

    static func deserialize(_ byteStream: ByteStream) -> TransactionInput {
        let previousOutput = TransactionOutPoint.deserialize(byteStream)
        let scriptLength = byteStream.read(VarInt.self)
        let signatureScript = byteStream.read(Data.self, count: Int(scriptLength.underlyingValue))
        let sequence = byteStream.read(UInt32.self)
        return TransactionInput(previousOutput: previousOutput, signatureScript: signatureScript, sequence: sequence)
    }
}

// MARK: - TransactionInput+Script

extension TransactionInput {

    static func fromPubKeyHashOut(txHashBuf: Data, txOutNum: UInt32, txOut: TransactionOutput, pubKey: PublicKey) -> TransactionInput {
        let script = Script()

        if txOut.getScript().isPayToPublicKeyHashOutScript {
            try! script.append(.OP_0)
            try! script.appendData(pubKey.toDer()) // TODO: Should force the compressed key?
        }

        return TransactionInput(
            previousOutput: TransactionOutPoint(
                hash: txHashBuf,
                index: txOutNum
            ),
            signatureScript: script.data,
            sequence: 0xffffffff
        )
    }

    func withFilledSig(nScriptChunk: Int, sig: Data) -> TransactionInput {

        let script = Script(data: signatureScript)!

        let signedScript = try! Script().appendData(sig)

        var chunks = script.scriptChunks
        chunks[nScriptChunk] = signedScript.chunk(at: 0)

        let filledScript = Script(chunks: chunks)

        return TransactionInput(
            previousOutput: previousOutput,
            signatureScript: filledScript.data,
            sequence: sequence
        )
    }

}
