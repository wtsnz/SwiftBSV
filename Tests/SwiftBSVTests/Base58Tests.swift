//
//  Base58Tests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class Base58Tests: XCTestCase {

    let buffer: [UInt8] = [0, 1, 2, 3, 253, 254, 255]
    let enc = "1W7N4RuG"

    func testEncode() {
        let encoded = Base58.encode(Data(buffer))
        XCTAssertEqual(enc, encoded)
    }

    func testDecode() {
        let encoded = Base58.decode(enc)
        XCTAssertEqual(Data(buffer), encoded)
    }

}
