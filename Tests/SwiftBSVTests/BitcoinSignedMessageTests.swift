//
//  BitcoinSignedMessageTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-23.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import XCTest
@testable import SwiftBSV

class BitcoinSignedMessageTests: XCTestCase {

    func testSign() {
        let message = "this is my message"
        let privateKey = PrivateKey()
        let sigString = BitcoinSignedMessage.sign(message: message, privateKey: privateKey)
        let sigData = Data.init(base64Encoded: sigString)

        XCTAssertEqual(sigData?.count, 1 + 32 + 32)
    }

    func testVerify() {
        let message = "hello!"
        let privateKey = PrivateKey()
        let address = privateKey.address
        let sigString = BitcoinSignedMessage.sign(message: message, privateKey: privateKey)

        let valid = BitcoinSignedMessage.verify(message: message, signature: sigString, address: address)

        XCTAssertEqual(valid, true)
    }

    func testVerifyKnown2() {
        let message = "hello!"
        let address = Address(fromString: "1D7ZaBLeT3FFr1mcKAWorZHdE18kEVvuaY")!

        let sigString = "IOsRLk8/CBpLvOecpV0kh4ajjgpUH04T3kkJRPJng5kMOe3Az0gwGx2n8dHyooGykrqB6SuMCPtahZ5EN/TcZzg="

        let valid = BitcoinSignedMessage.verify(message: message, signature: sigString, address: address)
        XCTAssertTrue(valid)
    }

    func testVerifyKnown3() {
        let message = "This is an example of a signed message."
        let address = Address(fromString: "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN")!

        let sigString = "HDQI/lKj45lyBQgmXZDQe6uNxbIA0ho9+04t9BnDtX2gNqEwyht4CsewAtIQhVtwvjArQm4XKEy8Wwjl+aws/NE="

        let valid = BitcoinSignedMessage.verify(message: message, signature: sigString, address: address)
        XCTAssertTrue(valid)
    }

}

