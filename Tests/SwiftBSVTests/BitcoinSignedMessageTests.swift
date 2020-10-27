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

    func testVerifyKnown() {
        let message = "this is my message"
        let address = Address(fromString: "1CKTmxj6DjGrGTfbZzVxnY4Besbv8oxSZb")!

        let sigString = "IOrTlbNBI0QO990xOw4HAjnvRl/1zR+oBMS6HOjJgfJqXp/1EnFrcJly0UcNelqJNIAH4f0abxOZiSpYmenMH4M="

        let valid = BitcoinSignedMessage.verify(message: message, signature: sigString, address: address)
        XCTAssertTrue(valid)
    }

}

