//
//  SignatureTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-26.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class SignatureTests: XCTestCase {

    func testParseDer() {
        let data = Data(hex: "3044022075fc517e541bd54769c080b64397e32161c850f6c1b2b67a5c433affbb3e62770220729e85cc46ffab881065ec07694220e71d4df9b2b8c8fd12c3122cf3a5efbcf2")

        let sig = Signature.parseDER(buffer: data)

        XCTAssertEqual(sig?.r.hex, "75fc517e541bd54769c080b64397e32161c850f6c1b2b67a5c433affbb3e6277")
        XCTAssertEqual(sig?.s.hex, "729e85cc46ffab881065ec07694220e71d4df9b2b8c8fd12c3122cf3a5efbcf2")
    }

    func testParseTxBuffer() {
        let data = Data(hex: "30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e7201")

        let sig = Signature(txFormatBuffer: data)

        XCTAssertEqual(sig?.r.hex, "008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa")
        XCTAssertEqual(sig?.s.hex, "0993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72")

        XCTAssertEqual(sig?.nHashType?.rawValue, 1)
    }

    func testParseTxBufferAndRecreate() {
        let data = Data(hex: "30450221008bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa02200993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e7201")

        let sig = Signature(txFormatBuffer: data)

        XCTAssertEqual(sig?.toTxFormat().hex, data.hex)
    }

    func testKnownRsValues() {

        let r = BInt("63173831029936981022572627018246571655303050627048489594159321588908385378810")!

        let s = BInt("4331694221846364448463828256391194279133231453999942381442030409253074198130")!

        // 0
        var sig = Signature(r: r.data, s: s.data, nHashType: nil, recovery: 0, compressed: nil)
        var data = sig.toBuffer().hex

        XCTAssertEqual(data, "1f8bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa0993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72")


        // 1
        sig = Signature.init(r: r.data, s: s.data, nHashType: nil, recovery: 1, compressed: nil)
        data = sig.toBuffer().hex

        XCTAssertEqual(data, "208bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa0993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72")

        // 2
        sig = Signature.init(r: r.data, s: s.data, nHashType: nil, recovery: 2, compressed: nil)
        data = sig.toBuffer().hex

        XCTAssertEqual(data, "218bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa0993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72")

        // 3
        sig = Signature.init(r: r.data, s: s.data, nHashType: nil, recovery: 3, compressed: nil)
        data = sig.toBuffer().hex

        XCTAssertEqual(data, "228bab1f0a2ff2f9cb8992173d8ad73c229d31ea8e10b0f4d4ae1a0d8ed76021fa0993a6ec81755b9111762fc2cf8e3ede73047515622792110867d12654275e72")
    }

}
