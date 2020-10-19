//
//  AddressTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-19.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class AddressTests: XCTestCase {

    let pubKeyHash = Data(hex: "3c3fa3d4adcaf8f52d5b1843975e122548269937")
    let versionByteNum = 0
    let buffer = Data(hex: "003c3fa3d4adcaf8f52d5b1843975e122548269937")
    let string = "16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r"

    func testAddress() {
        let address = Address(buffer: buffer)
        XCTAssertEqual(address?.toString(), string)

        let address2 = Address(fromString: string)
        XCTAssertEqual(address2?.toString(), string)
    }

    func testAddressCompressedPublicKeys() {
        let publicKey1 = PublicKey(fromDer: Data(hex: "0285e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b004"))!
        let address = Address(publicKey1)

        XCTAssertEqual(address.toString(), "19gH5uhqY6DKrtkU66PsZPUZdzTd11Y7ke")
    }

    func testAddressUncompressedPublicKeys() {
        var publicKey1 = PublicKey(fromDer: Data(hex: "0285e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b004"))!
        publicKey1.isCompressed = false
        let address = Address(publicKey1)

        XCTAssertEqual(address.toString(), "16JXnhxjJUhxfyx4y6H4sFcxrgt8kQ8ewX")
    }

    func testAddressFromPrivateKey() {
        let privateKey = PrivateKey()
        let publicKey = privateKey.publicKey
        let address1 = Address(privateKey)
        let address2 = Address(publicKey)
        XCTAssertEqual(address1.toString(), address2.toString())
    }

}
