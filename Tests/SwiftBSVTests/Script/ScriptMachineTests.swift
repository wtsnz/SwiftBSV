//
//  ScriptMachineTests.swift
//
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

import XCTest
@testable import SwiftBSV
import Foundation

class ScriptMachineTests: XCTestCase {

    func testChunksFromStringToData() {
        var chunks = ChunkHelpers.chunksFromString("OP_0 OP_PUSHDATA4 3 0x010203 OP_0")
        var buffer = ChunkHelpers.chunksToBuffer(chunks)
        var string = ChunkHelpers.chunksToString(chunks)
        var bufferChunks = ChunkHelpers.chunksFromBuffer(buffer)
        XCTAssertEqual(chunks, bufferChunks)
        XCTAssertEqual(buffer.hex, "004e0300000001020300")
        XCTAssertEqual(string, "OP_0 OP_PUSHDATA4 3 0x010203 OP_0")

        chunks = ChunkHelpers.chunksFromString("OP_DUP OP_HASH160 20 0x1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG")
        buffer = ChunkHelpers.chunksToBuffer(chunks)
        string = ChunkHelpers.chunksToString(chunks)
        bufferChunks = ChunkHelpers.chunksFromBuffer(buffer)
        XCTAssertEqual(chunks, bufferChunks)
        XCTAssertEqual(buffer.hex, "76a9141451baa3aad777144a0759998a03538018dd7b4b88ac")
        XCTAssertEqual(string, "OP_DUP OP_HASH160 20 0x1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG")
        

        chunks = ChunkHelpers.chunksFromString("OP_SHA256 32 0x8cc17e2a2b10e1da145488458a6edec4a1fdb1921c2d5ccbc96aa0ed31b4d5f8 OP_EQUALVERIFY OP_DUP OP_HASH160 20 0x1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_EQUALVERIFY OP_DUP OP_HASH160 20 0x1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG")
        buffer = ChunkHelpers.chunksToBuffer(chunks)
        string = ChunkHelpers.chunksToString(chunks)
        bufferChunks = ChunkHelpers.chunksFromBuffer(buffer)
        XCTAssertEqual(chunks, bufferChunks)
        XCTAssertEqual(buffer.hex, "a8208cc17e2a2b10e1da145488458a6edec4a1fdb1921c2d5ccbc96aa0ed31b4d5f88876a9141451baa3aad777144a0759998a03538018dd7b4b88ad8876a9141451baa3aad777144a0759998a03538018dd7b4b88ac")
        XCTAssertEqual(string, "OP_SHA256 32 0x8cc17e2a2b10e1da145488458a6edec4a1fdb1921c2d5ccbc96aa0ed31b4d5f8 OP_EQUALVERIFY OP_DUP OP_HASH160 20 0x1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_EQUALVERIFY OP_DUP OP_HASH160 20 0x1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG")
    }

    func testChunksFromBitcoindString() {

        let bitcoindString = "'Azzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' EQUAL"
        let buffer = ChunkHelpers.bitcoindStringToBuffer(bitcoindString)
        let chunks = ChunkHelpers.chunksFromBuffer(buffer)
        let calculatedBitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks)

        let te2 = "0x4b417a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a EQUAL"

        XCTAssertEqual(calculatedBitcoindString, te2)
    }

    func testChunksFromAsmString() {

        let asmString = "OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG"

        let chunks = ChunkHelpers.chunksFromAsmString(asmString)
        XCTAssertEqual(chunks[0].opCodeNum, OpCode.OP_DUP.value)
        XCTAssertEqual(chunks[1].opCodeNum, OpCode.OP_HASH160.value)
        XCTAssertEqual(chunks[2].opCodeNum, 20)
        XCTAssertEqual(chunks[2].buffer?.hex, "f4c03610e60ad15100929cc23da2f3a799af1725")
        XCTAssertEqual(chunks[3].opCodeNum, OpCode.OP_EQUALVERIFY.value)
        XCTAssertEqual(chunks[4].opCodeNum, OpCode.OP_CHECKSIG.value)
    }

    func testChunksFromKnownProblematicAsmString() {
        let asmString = "OP_RETURN 026d02 0568656c6c6f"
        let chunks = ChunkHelpers.chunksFromAsmString(asmString)
        let calculatedAsmString = ChunkHelpers.chunksToAsmString(chunks)

        XCTAssertEqual(asmString, calculatedAsmString)
    }

    func testScriptFromHex() {
        let data = Data([OpCodeFactory.get(with: "OP_0").value])
        let script = Script(hex: data.hex)

        dump(script?.string)
        XCTAssertEqual(script?.scriptChunks.count, 1)
        XCTAssertEqual(script?.chunk(at: 0).opcodeValue, Op0().value)
    }

    func testssss() {
        let thisSourceFile = URL(fileURLWithPath: #file)
        let testsDirectory = thisSourceFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        let resourcesURL = testsDirectory.appendingPathComponent("Resources")

        let validScriptJsonUrl = resourcesURL
            .appendingPathComponent("vectors")
            .appendingPathComponent("bitcoind")
            .appendingPathComponent("script_valid.json")


        let json = try! JSONSerialization.jsonObject(
            with: try! Data(contentsOf: validScriptJsonUrl),
            options: []
        )

        let array = json as! NSArray

        array.forEach { (contents) in
            let row = contents as! NSArray

            if row.count == 1 {
                return
            }

            do {
                let scriptSig = row[0] as! NSString

    //            let scriptPubKey = row[1] as! NSString
    //            let flags = row[2] as! NSString
    //            let expectedError = row[3] as! NSString


                print(scriptSig)
                let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig as String)
                let chunks = ChunkHelpers.chunksFromBuffer(buffer)
                let string = ChunkHelpers.chunksToString(chunks)
                let chunks2 = ChunkHelpers.chunksFromString(string)
                let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks2)

                XCTAssertEqual(bitcoindString, scriptSig as String)
            }

            do {
                let scriptSig = row[1] as! NSString

    //            let scriptPubKey = row[1] as! NSString
    //            let flags = row[2] as! NSString
    //            let expectedError = row[3] as! NSString


                print(scriptSig)
                let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig as String)
                let chunks = ChunkHelpers.chunksFromBuffer(buffer)
                let string = ChunkHelpers.chunksToString(chunks)
                let chunks2 = ChunkHelpers.chunksFromString(string)
                let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks2)

                XCTAssertEqual(bitcoindString, scriptSig as String)

            }

        }

    }

    func testCheck() {
        XCTFail()
//
//        // Transaction in testnet3
//        // https://api.blockcypher.com/v1/btc/test3/txs/0189910c263c4d416d5c5c2cf70744f9f6bcd5feaf0b149b02e5d88afbe78992
//        let prevTxID = "1524ca4eeb9066b4765effd472bc9e869240c4ecb5c1ee0edb40f8b666088231"
//        // hash.reversed = txid
//        let hash = Data(Data(hex: prevTxID)!.reversed())
//        let index: UInt32 = 1
//        let outpoint = TransactionOutPoint(hash: hash, index: index)
//
//        let balance: UInt64 = 169012961
//        let amount: UInt64  =  50000000
//        let fee: UInt64     =  10000000
//        let toAddress = "mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB" // https://testnet.coinfaucet.eu/en/
//
//        let privateKey = try! PrivateKey(wif: "92pMamV6jNyEq9pDpY4f6nBy9KpV2cfJT4L5zDUYiGqyQHJfF1K")
//
//        let fromPublicKey = privateKey.publicKey()
//        let fromPubKeyHash = Crypto.sha256ripemd160(fromPublicKey.data)
//        let toPubKeyHash = Base58Check.decode(toAddress)!.dropFirst()
//
//        // unsigned tx
//        let lockingScript1 = Script.buildPublicKeyHashOut(pubKeyHash: toPubKeyHash)
//        let lockingScript2 = Script.buildPublicKeyHashOut(pubKeyHash: fromPubKeyHash)
//
//        let sending = TransactionOutput(value: amount, lockingScript: lockingScript1)
//        let payback = TransactionOutput(value: balance - amount - fee, lockingScript: lockingScript2)
//        let subScript = Data(hex: "76a9142a539adfd7aefcc02e0196b4ccf76aea88a1f47088ac")!
//        let inputForSign = TransactionInput(previousOutput: outpoint, signatureScript: subScript, sequence: UInt32.max)
//        let unsignedTx = Transaction(version: 1, inputs: [inputForSign], outputs: [sending, payback], lockTime: 0)
//
//        // sign
//        let hashType: BTCSighashType = SighashType.BTC.ALL
//        let utxoToSign = TransactionOutput(value: balance, lockingScript: subScript)
//        let helper = BTCSignatureHashHelper(hashType: hashType)
//        let _txHash = helper.createSignatureHash(of: unsignedTx, for: utxoToSign, inputIndex: 0)
//        guard let signature: Data = try? Crypto.sign(_txHash, privateKey: privateKey) else {
//            XCTFail("Failed to sign tx.")
//            return
//        }
//
//        // unlock script
//        XCTAssertEqual(fromPublicKey.pubkeyHash.hex, "2a539adfd7aefcc02e0196b4ccf76aea88a1f470")
//        let unlockScript: Script = try! Script()
//            .appendData(signature + hashType.uint8)
//            .appendData(fromPublicKey.data)
//
//        // signed tx
//        let txin = TransactionInput(previousOutput: outpoint, signatureScript: unlockScript.data, sequence: UInt32.max)
//        let signedTx = Transaction(version: 1, inputs: [txin], outputs: [sending, payback], lockTime: 0)
//
//        // crypto verify
//        do {
//            let sigData: Data = signature + hashType.uint8
//            let pubkeyData: Data = fromPublicKey.data
//            let result = try Crypto.verifySigData(for: signedTx, inputIndex: 0, utxo: utxoToSign, sigData: sigData, pubKeyData: pubkeyData)
//            XCTAssertTrue(result)
//        } catch (let err) {
//            XCTFail("Crypto verifySigData failed. \(err)")
//        }
//
//        // script machine verify
//        do {
//            let result = try ScriptMachine.verifyTransaction(signedTx: signedTx, inputIndex: 0, utxo: utxoToSign)
//            XCTAssertTrue(result)
//        } catch (let err) {
//            XCTFail("Script machine verify failed. \(err)")
//        }
    }
}
