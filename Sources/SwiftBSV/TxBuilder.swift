//
//  TxBuilder.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

enum TxBuilderError: Error {
    case invalidNumberOfInputs
    case missingChangeOutput
    case invalidNumberOfOutputs
    case changeOutputLessThanDust
    case inputAmountLessThanOutputAmount
}

class TxBuilder {

    private(set) var transaction: Transaction = .empty
    private var transactionInputs: [TransactionInput] = []
    private var transactionOutputs: [TransactionOutput] = []

    private var uTxOutMap = TxOutMap()
    private var sigOperations = SigOperations()

    private(set) var changeScript: Script?
    private(set) var changeAmount: UInt64?

    private(set) var feeAmount: UInt64 = 0
    private(set) var dustChangeToFees = true

    private(set) var nLockTime: UInt32 = 0
    private(set) var version: UInt32 = 1

    /// The desired fee per Kb
    private(set) var dust: UInt64 = Network.mainnet.txBuilder.dust
    private(set) var feePerKbNum: Float = Network.mainnet.txBuilder.feePerKb

    init() {

    }

    @discardableResult
    func setNLockTime(_ nLockTime: UInt32) -> Self {
        self.nLockTime = nLockTime
        return self
    }

    @discardableResult
    func setVersion(_ version: UInt32) -> Self {
        self.version = version
        return self
    }

    @discardableResult
    func setFeePerKb(_ fee: Float) -> Self {
        self.feePerKbNum = fee
        return self
    }

    @discardableResult
    func setChangeAddress(_ changeAddress: Address) -> Self {
        let script: Script = Script.buildPublicKeyHashOut(pubKeyHash: changeAddress.hashBuffer)
        setChangeScript(script)
        return self
    }

    @discardableResult
    func setChangeScript(_ changeScript: Script) -> Self {
        self.changeScript = changeScript
        return self
    }

    @discardableResult
    func inputFromScript(_ txHashBuffer: Data, txOutNum: UInt32, txOut: TransactionOutput, script: Script, nSequence: UInt32) -> Self {
        let txIn = TransactionInput(
            previousOutput: TransactionOutPoint(
                hash: txHashBuffer,
                index: txOutNum
            ),
            signatureScript: script.data,
            sequence: nSequence
        )
        transactionInputs.append(txIn)

        uTxOutMap.set(txHashBuf: txHashBuffer, txOutNum: txOutNum, txOut: txOut)

        return self
    }

    @discardableResult
    func addSigOperation(_ txHashBuf: Data, txOutNum: UInt32, nScriptChunk: UInt32, type: SigOperation.OperationType, addressString: String, nHashType: SighashType) -> Self {
        sigOperations.addOne(txHashBuf: txHashBuf, txOutNum: txOutNum, nScriptChunk: nScriptChunk, addressString: addressString, nHashType: nHashType)
        return self
    }

    @discardableResult
    func inputFromPubKeyHash(txHashBuffer: Data, txOutNum: UInt32, txOut: TransactionOutput, pubKey: PublicKey, nSequence: UInt32 = 0xffffffff, nHashType: SighashType = BSVSighashType.ALL) -> Self {

        let transactionInput = TransactionInput.fromPubKeyHashOut(
            txHashBuf: txHashBuffer,
            txOutNum: txOutNum,
            txOut: txOut,
            pubKey: pubKey
        )

        transactionInputs.append(transactionInput)

        uTxOutMap.set(txHashBuf: txHashBuffer, txOutNum: txOutNum, txOut: txOut)

        let addressString = pubKey.address.toString()
        addSigOperation(txHashBuffer, txOutNum: txOutNum, nScriptChunk: 0, type: .sig, addressString: addressString, nHashType: nHashType)
        addSigOperation(txHashBuffer, txOutNum: txOutNum, nScriptChunk: 1, type: .pubkey, addressString: addressString, nHashType: nHashType)

        return self
    }

    @discardableResult
    func outputToAddress(value: UInt64, address: Address) -> Self {
        let script: Script = Script.buildPublicKeyHashOut(pubKeyHash: address.hashBuffer)
        outputToScript(value: value, script: script)
        return self
    }

    @discardableResult
    func outputToScript(value: UInt64, script: Script) -> Self {
        let txOut = TransactionOutput(value: value, lockingScript: script.data)
        transactionOutputs.append(txOut)
        return self
    }

    /// Add the outputs to the transaction and return the total amount
    func buildOutputs() -> UInt64 {
        var totalOutputValue = UInt64()

        for txOut in transactionOutputs {
            // TODO: check if output amount is less than dust, and the output is an opreturn.
            //if (txOut.value < dust && !txOut.script.isOpReturn && !txOut.script.isSafeDataOut) {
            //  throw error!
            //
            totalOutputValue += txOut.value
            transaction.addTransactionOutput(txOut)
        }

        return totalOutputValue
    }

    func buildInputs(outAmount: UInt64, extraInputsNum: UInt32 = 0) -> UInt64 {
        var totalInputAmount = UInt64()
        var extraInputsNum = extraInputsNum

        for txIn in transactionInputs {
            if let txOut = uTxOutMap.get(txHashBuf: txIn.previousOutput.hash, txOutNum: txIn.previousOutput.index) {
                totalInputAmount += txOut.value
                transaction.addTransactionInput(txIn)

                if totalInputAmount >= outAmount {
                    if extraInputsNum <= 0 {
                        break
                    }
                    extraInputsNum -= 1
                }

            } else {
                fatalError("TxBuilder: Missing txOut in uTxOutMap")
            }

        }

        return totalInputAmount
    }

    // Thanks to SigOperations, if those are accurately used, then we can
    // accurately estimate what the size of the transaction is going to be once
    // all the signatures and public keys are inserted.
    func estimateSize() -> Int {
        // largest possible sig size. final 1 is for pushdata at start. second to
        // final is sighash byte. the rest are DER encoding.
        let sigSize = 1 + 1 + 1 + 1 + 32 + 1 + 1 + 32 + 1 + 1
        // length of script, y odd, x value - assumes compressed public key
        let pubKeySize = 1 + 1 + 33

        var size = transaction.serialized().count

        for txIn in transactionInputs {
            let sigOperations = self.sigOperations.get(txHashBuf: txIn.previousOutput.hash, txOutNum: txIn.previousOutput.index) ?? []

            for sigOperation in sigOperations {
                size -= Int(txIn.scriptLength.underlyingValue)
                switch sigOperation.type {
                case .pubkey:
                    size += pubKeySize
                case .sig:
                    size += sigSize
                }
            }
        }

        size += 1 // assume txInsVi increases by 1 byte

        return size
    }

    func estimateFee(extraFeeAmount: UInt64 = 0) -> UInt64 {
        // new style pays lower fees - rounds up to satoshi, not per kb:
        let fee = Float(estimateSize()) / 1000 * feePerKbNum
        return UInt64(fee) + extraFeeAmount
    }

    @discardableResult
    func build(useAllInputs: Bool) throws -> TxBuilder {
        var minFeeAmount = UInt64()
        self.changeAmount = 0

        if transactionInputs.count <= 0 {
            throw TxBuilderError.invalidNumberOfInputs
        }

        guard let changeScript = changeScript else {
            throw TxBuilderError.missingChangeOutput
        }

        var extraInputsNum = useAllInputs ? UInt32(transactionInputs.count - 1) : 0
        while (extraInputsNum < transactionInputs.count) {

            transaction = Transaction.empty
            let outputAmount = buildOutputs()

            // Add temporary change output transaction.
            let changeTxOut = TransactionOutput(value: changeAmount!, lockingScript: changeScript.data)
            transaction.addTransactionOutput(changeTxOut)

            let inputAmount = buildInputs(outAmount: outputAmount, extraInputsNum: extraInputsNum)

            // Set change amount from inAmountBn - outAmountBn
            changeAmount = inputAmount - outputAmount

            minFeeAmount = estimateFee()
            if changeAmount! >= minFeeAmount && (changeAmount! - minFeeAmount) > dust {
                break
            }

            extraInputsNum += 1
        }


        // Calculate fee and change
        if changeAmount! >= minFeeAmount {

            // Subtract fee from change
            feeAmount = minFeeAmount
            changeAmount = changeAmount! - feeAmount

            // Recreate the change transaction output with the correct fee
            _ = transaction.removeLastTransactionOutput()
            let changeTxOut = TransactionOutput(value: changeAmount!, lockingScript: changeScript.data)
            transaction.addTransactionOutput(changeTxOut)

            // Check change amount is valid
            if changeAmount! < dust {
                if dustChangeToFees {
                    // Remove the change output since it is less that dust and the
                    // builder has requested that dust be sent to fees
                    _ = transaction.removeLastTransactionOutput()
                    feeAmount += changeAmount!
                    changeAmount = 0
                } else {
                    throw TxBuilderError.changeOutputLessThanDust
                }
            }

            transaction.setLockTime(nLockTime)
            transaction.setVersion(version)

            if transaction.outputs.count == 0 {
                throw TxBuilderError.invalidNumberOfOutputs
            }

            return self

        } else {
            // not enough input for outputs and fees
            throw TxBuilderError.inputAmountLessThanOutputAmount
        }

    }

    // MARK: - Signatures

    func getSig(privateKey: PrivateKey, nHashType: BSVSighashType = .ALL, nIn: Int, subScript: Script, flags: TransactionSigHashFlags = .scriptEnableSighashForkId) -> Data {
        var value = UInt64()

        if nHashType.hasForkId && flags.contains(.scriptEnableSighashForkId) {
            let txHashBuf = transactionInputs[nIn].previousOutput.hash
            let txOutNum = transactionInputs[nIn].previousOutput.index
            if let txOut = uTxOutMap.get(txHashBuf: txHashBuf, txOutNum: txOutNum) {
                value = txOut.value
            }
        }

        return transaction.sign(privateKey: privateKey, nHashType: nHashType, nIn: nIn, subScript: subScript, value: value, flags: flags)
    }

    /// Sign the input with the private key. Only supports PayToPublicKeyHash inputs
    @discardableResult
    func signInTx(nIn: Int, privateKey: PrivateKey, txOut: TransactionOutput? = nil, nScriptChunk: Int? = nil, nHashType: BSVSighashType = .ALL, flags: TransactionSigHashFlags = .scriptEnableSighashForkId) -> Self {

        var nScriptChunk = nScriptChunk
        let txIn = transaction.inputs[nIn]
        let script = Script(data: txIn.signatureScript)!

        if nScriptChunk == nil && script.isPubKeyHashIn {
            nScriptChunk = 0
        }

        guard let scriptChunk = nScriptChunk else {
            fatalError()
        }

        let txHashBuf = txIn.previousOutput.hash
        let txOutNum = txIn.previousOutput.index

        var txOut = txOut
        if txOut == nil {
            txOut = uTxOutMap.get(txHashBuf: txHashBuf, txOutNum: txOutNum)
        }

        if txOut == nil {
            fatalError()
        }

        let outputScript = txOut!.lockingScript
        let subScript = Script(data: outputScript)!
        let sig = getSig(privateKey: privateKey, nHashType: nHashType, nIn: nIn, subScript: subScript, flags: flags)

        fillSig(nIn: nIn, nScriptChunk: scriptChunk, sig: sig, sigHashType: nHashType, publicKey: privateKey.publicKey)

        return self
    }

    func fillSig(nIn: Int, nScriptChunk: Int, sig: Data, sigHashType: SighashType, publicKey: PublicKey) {
        transaction.fillSig(nIn: nIn, nScriptChunk: nScriptChunk, sig: sig, sigHashType: sigHashType, publicKey: publicKey)
    }

}
