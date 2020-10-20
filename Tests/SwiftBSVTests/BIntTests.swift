//
//  BIntTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class BIntTests: XCTestCase {

    func testBIntMod() {
        let bn1 = BInt(-50)
        let bn2 = BInt(25)
        let bn3 = bn1 % bn2

        XCTAssertEqual(bn3.asString(radix: 10), "0")
    }

    func testBnToFromScriptBuffer() {

        // The hex string should keep leading 0's
        var number = BInt(520)
        XCTAssertEqual(number.toHexString(), "0208")

        // toScriptNumBuffer should be correct

        number = BInt(-1)
        var data = Data(hex: "81")
        XCTAssertEqual(number.toScriptNumBuffer(), data)
        XCTAssertEqual(BInt(fromScriptNumBuffer: data), number)

        number = BInt(0)
        data = Data(hex: "00")
        XCTAssertEqual(number.toScriptNumBuffer(), data)
        XCTAssertEqual(BInt(fromScriptNumBuffer: data), number)

        number = BInt(1)
        data = Data(hex: "01")
        XCTAssertEqual(number.toScriptNumBuffer(), data)
        XCTAssertEqual(BInt(fromScriptNumBuffer: data), number)

        number = BInt(123456)
        data = Data(hex: "40e201")
        XCTAssertEqual(number.toScriptNumBuffer(), data)
        XCTAssertEqual(BInt(fromScriptNumBuffer: data), number)
    }

    func testBNtoHexString() {

        var number = BInt(-1)
        var hexString = "-1"
        XCTAssertEqual(number.toHexString(), hexString)

        number = BInt(0)
        hexString = "00"
        XCTAssertEqual(number.toHexString(), hexString)

        number = BInt(1)
        hexString = "01"
        XCTAssertEqual(number.toHexString(), hexString)

        number = BInt(123456)
        hexString = "01e240"
        XCTAssertEqual(number.toHexString(), hexString)
    }
}
