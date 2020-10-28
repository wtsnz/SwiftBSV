//
//  PrivateKeyTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import XCTest
@testable import SwiftBSV

class PrivateKeyTests: XCTestCase {

    let buf = Data(hex: "96c132224121b509b7d0a16245e957d9192609c5637c6228311287b1be21627a")
    let enctestnet = "cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG"
    let enctu = "92jJzK4tbURm1C7udQXxeCBvXHoHJstDXRxAMouPG1k1XUaXdsu"
    let encmainnet = "L2Gkw3kKJ6N24QcDuH4XDqt9cTqsKTVNDGz1CRZhk9cq4auDUbJy"
    let encmu = "5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un"


    func testRandom() {
        let privateKey = PrivateKey(network: .testnet)
        XCTAssertEqual(privateKey.toWif().prefix(1), "c")
    }

    func testBInt() {
        let bn = BInt(0)
        let privateKey = PrivateKey(bn: bn, network: .testnet)
        XCTAssertEqual(privateKey.bn.asString(radix: 16), bn.asString(radix: 16))
    }

    func testMainnet() {
        let privateKey = PrivateKey(bn: BInt(data: buf))
        XCTAssertEqual(privateKey.toWif(), encmainnet)
    }

    func testUncompressedTestnet() {
        let privateKey = PrivateKey(bn: BInt(data: buf), isCompressed: false, network: .testnet)
        XCTAssertEqual(privateKey.toWif(), enctu)
    }

    func testUncompressedMainnet() {
        let privateKey = PrivateKey(bn: BInt(data: buf), isCompressed: false, network: .mainnet)
        XCTAssertEqual(privateKey.toWif(), encmu)
    }

    func testFromWif() {
        XCTAssertEqual(PrivateKey(wif: encmu)?.toWif(), encmu)
    }

    func testFrom() {
        let p = "cT5XuiE2xs65HnMMgKRd4vkbNukYqqtWUzL5SMRPPE4VvT3FT3xn"

        let privateKey = PrivateKey(wif: p, network: .testnet)

        XCTAssertEqual(privateKey?.toWifData().hex, "efa404f0ddada148bed16adb2b8b0be3736cc890f2f58396b6cf9df2548cd6561101")

        let publicKey = privateKey?.publicKey

        let address = Address(publicKey!, network: .testnet)

        XCTAssertEqual(address.toString(), "mpcd4bwYbTiqqZZ2s26eyv1MZTpnbMW6R7")
    }

//    func testBitcoin() {
//        let address = "1MVEQHYUv1bWiYJB77NNEEEdbmNFEoW5q6"
//        let rawPk = "0e66055a963cc3aecb185cf795de476cf290c88db671297da041b7f7377e6f9c"
//
//        let hexPk = "0e66055a963cc3aecb185cf795de476cf290c88db671297da041b7f7377e6f9c"
//        let uncompressedPk = "5HvdNYs1baLY7vpnmb2osg5gZHvAFxDiBoCujs2vfTjC442rzSK"
//        let compressedPk = "KwhhY7djdc9EMaZw1oCytfVfbXfdrzj6newZnBqVrkyDnKVWiCmJ"
//        [hexPk, compressedPk, uncompressedPk].forEach {
//            testImportFromPK(coin: .bitcoin, privateKey: $0, address: address, raw: rawPk)
//        }
//    }
//
//    func testImportFromPK(coin: Coin, privateKey: String, address: String, raw: String) {
//        let pk = PrivateKey(pk: privateKey, coin: coin)
////        XCTAssertEqual(pk!.publicKey.address, address)
//        XCTAssertEqual(pk?.raw, Data(hex: raw))
//    }
    
}

