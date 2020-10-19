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

}
