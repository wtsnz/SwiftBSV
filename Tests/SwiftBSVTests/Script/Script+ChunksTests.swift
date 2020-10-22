//
//  Script+ChunksTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-20.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import XCTest
@testable import SwiftBSV

class ScriptPlusChunksTests: XCTestCase {

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

    func _testForDebugging() {
        let scriptSig = "0x4c01"
//        let scriptSig = "0x21 0x03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640 CHECKSIG"

        let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig)
        let chunks = ChunkHelpers.chunksFromBuffer(buffer)
        let _ = ChunkHelpers.chunksToString(chunks)
        let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks)

        let buffer2 = ChunkHelpers.bitcoindStringToBuffer(bitcoindString)
        let chunks2 = ChunkHelpers.chunksFromBuffer(buffer2)
        let bitcoindString2 = ChunkHelpers.bitcoindStringFromChunks(chunks2)

        XCTAssertEqual(bitcoindString, bitcoindString2)
    }

    func testReadsScriptValidVectors() {
        let json = TestHelpers.jsonResource(pathComponents: [
            "vectors",
            "bitcoind",
            "script_valid.json"
        ])

        let array = json as! NSArray

        array.forEach { (contents) in
            let row = contents as! NSArray

            if row.count == 1 {
                return
            }

            do {
                let scriptSig = row[0] as! NSString as String

                let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig)
                let chunks = ChunkHelpers.chunksFromBuffer(buffer)
                let _ = ChunkHelpers.chunksToString(chunks)
                let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks)

                let buffer2 = ChunkHelpers.bitcoindStringToBuffer(bitcoindString)
                let chunks2 = ChunkHelpers.chunksFromBuffer(buffer2)
                let bitcoindString2 = ChunkHelpers.bitcoindStringFromChunks(chunks2)

                XCTAssertEqual(bitcoindString, bitcoindString2)
            }

            do {
                let scriptSig = row[1] as! NSString as String

                print(scriptSig)
                let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig)
                let chunks = ChunkHelpers.chunksFromBuffer(buffer)
                let _ = ChunkHelpers.chunksToString(chunks)
                let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks)

                let buffer2 = ChunkHelpers.bitcoindStringToBuffer(bitcoindString)
                let chunks2 = ChunkHelpers.chunksFromBuffer(buffer2)
                let bitcoindString2 = ChunkHelpers.bitcoindStringFromChunks(chunks2)

                XCTAssertEqual(bitcoindString, bitcoindString2)
            }

        }

    }

    func testReadsScriptInvalidVectors() {

        let json = TestHelpers.jsonResource(pathComponents: [
            "vectors",
            "bitcoind",
            "script_invalid.json"
        ])

        let array = json as! NSArray

        array.forEach { (contents) in
            let row = contents as! NSArray

            if row.count == 1 {
                return
            }

            do {
                let scriptSig = row[0] as! NSString as String

                let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig)
                let chunks = ChunkHelpers.chunksFromBuffer(buffer)
                let _ = ChunkHelpers.chunksToString(chunks)
                let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks)

                let buffer2 = ChunkHelpers.bitcoindStringToBuffer(bitcoindString)
                let chunks2 = ChunkHelpers.chunksFromBuffer(buffer2)
                let bitcoindString2 = ChunkHelpers.bitcoindStringFromChunks(chunks2)

                XCTAssertEqual(bitcoindString, bitcoindString2)
            }

            do {
                let scriptSig = row[1] as! NSString as String

                print(scriptSig)
                let buffer = ChunkHelpers.bitcoindStringToBuffer(scriptSig)
                let chunks = ChunkHelpers.chunksFromBuffer(buffer)
                let _ = ChunkHelpers.chunksToString(chunks)
                let bitcoindString = ChunkHelpers.bitcoindStringFromChunks(chunks)

                let buffer2 = ChunkHelpers.bitcoindStringToBuffer(bitcoindString)
                let chunks2 = ChunkHelpers.chunksFromBuffer(buffer2)
                let bitcoindString2 = ChunkHelpers.bitcoindStringFromChunks(chunks2)

                XCTAssertEqual(bitcoindString, bitcoindString2)
            }

        }

    }

}
