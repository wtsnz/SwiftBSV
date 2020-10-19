//
//  PublicKeyTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class PublicKeyTests: XCTestCase {

    func testPublicKeyFromUncompressedDER() {

        let der = "041ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341"
        let publicKey = PublicKey(
            fromDer: Data(
                hex: der
            )
        )

        XCTAssertEqual(publicKey?.point.x.asString(radix: 16), "1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a")
        XCTAssertEqual(publicKey?.point.y.asString(radix: 16), "7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341")

        XCTAssertEqual(publicKey?.description, der)
    }

    func testPublicKeyFromCompressedDER() {

        let der = "031ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a"

        let publicKey = PublicKey(
            fromDer: Data(
                hex: der
            )
        )

        XCTAssertEqual(publicKey?.point.x.asString(radix: 16), "1ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a")
        XCTAssertEqual(publicKey?.point.y.asString(radix: 16), "7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341")
        XCTAssertEqual(publicKey?.description, der)
    }

    func testPublicKeyFromInvalidPublickKey() {

        let publicKey = PublicKey(
            fromDer: Data(
                hex: "091ff0fe0f7b15ffaa85ff9f4744d539139c252a49710fb053bb9f2b933173ff9a"
            )
        )

        XCTAssertNil(publicKey)
    }

}
