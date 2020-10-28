//
//  TransactionTests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-20.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation
import XCTest
@testable import SwiftBSV

class TransactionTests: XCTestCase {

    let tx2idhex =
      "8c9aa966d35bfeaf031409e0001b90ccdafd8d859799eb945a3c515b8260bcf2"
    static let tx2hex =
      "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
    let tx2buf = Data(hex: tx2hex)

    func testSigHashSingleBug() {
        var tx = Transaction.deserialize(tx2buf)
        tx.outputs = [tx.outputs[0]]

        let hashBuf = TransactionInputSigner.signatureHash(tx: tx, signatureVersion: .forkId, sighashType: SighashType.BTC.SINGLE, nIn: 1, subScript: Script(), value: 0)

        XCTAssertEqual(hashBuf.hex, "0000000000000000000000000000000000000000000000000000000000000001")
    }

    func testKnowntx() {
        let txraw = "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229"

        let tx = Transaction.deserialize(Data(hex: txraw))
        let sighash = 1864164639
        let hash = TransactionInputSigner.signatureHash(tx: tx, signatureVersion: .forkId, sighashType: SighashType(i: sighash), nIn: 2, subScript: Script(), value: 0)

        XCTAssertEqual(hash.hex, "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e")
    }

    func testKnowntx2() {
        let txraw = "b1c0b71804dff30812b92eefb533ac77c4b9fdb9ab2f77120a76128d7da43ad70c20bbfb990200000002536392693e6001bc59411aebf15a3dc62a6566ec71a302141b0c730a3ecc8de5d76538b30f55010000000665535252ac514b740c6271fb9fe69fdf82bf98b459a7faa8a3b62f3af34943ad55df4881e0d93d3ce0ac0200000000c4158866eb9fb73da252102d1e64a3ce611b52e873533be43e6883137d0aaa0f63966f060000000001abffffffff04a605b604000000000851006a656a630052f49a0300000000000252515a94e1050000000009abac65ab0052abab00fd8dd002000000000651535163526a2566852d"

        let tx = Transaction.deserialize(Data(hex: txraw))
        let serial = tx.serialized().hex

        XCTAssertEqual(txraw, serial)

        let sighash = Int(-1718831517)
        let script = Script(hex: "ac5363")!
        let hash = TransactionInputSigner.signatureHash(tx: tx, signatureVersion: .legacy, sighashType: SighashType(i: sighash), nIn: 0, subScript: script, value: 0)

        XCTAssertEqual(hash.hex, "b0dc030661783dd9939e4bf1a6dfcba809da2017e1b315a6312e5942d714cf05")
    }

    func testSighashVectors() {

        // --- Tx Sighash

        let bsvSighashJson = TestHelpers.jsonResource(pathComponents: [
            "vectors",
            "bitcoin-sv",
            "sighash.json"
        ])

        let bsvSighashJsonArray = bsvSighashJson as! NSArray

        bsvSighashJsonArray.forEach { vector in

            let vector = vector as! NSArray

            if vector.count == 1 {
                return
            }

            let raw_tx = Data(hex: vector[0] as! String)
            let raw_script = Data(hex: vector[1] as! String)
            let nIn = vector[2] as! NSNumber
            let sighashNsNumber = vector[3] as! NSNumber
            let sighashRegHex = vector[4] as! String
            let sighashOldHex = vector[5] as! String

            let script = Script(data: raw_script)!
            let tx = Transaction.deserialize(raw_tx)

            XCTAssertEqual(tx.serialized().hex, raw_tx.hex)

            let sighashValue = sighashNsNumber.intValue
            let sighashType = SighashType(i: sighashValue)

            let hashReg = TransactionInputSigner.signatureHash(tx: tx, signatureVersion: .forkId, sighashType: sighashType, nIn: Int(truncating: nIn), subScript: script, value: 0)

            let hashOld = TransactionInputSigner.signatureHash(tx: tx, signatureVersion: .legacy, sighashType: sighashType, nIn: Int(truncating: nIn), subScript: script, value: 0)


            XCTAssertEqual(hashReg.hex, sighashRegHex)
            XCTAssertEqual(hashOld.hex, sighashOldHex)
        }

        // --- Tx SigHash

        let txSigHashJson = TestHelpers.jsonResource(pathComponents: [
            "vectors",
            "bitcoind",
            "sighash.json"
        ])

        let txSigHashJsonArray = txSigHashJson as! NSArray

        txSigHashJsonArray.forEach { vector in
            let vector = vector as! NSArray

            if vector.count == 1 {
                return
            }

            let txBuf = Data(hex: vector[0] as! String)
            let scriptBuf = Data(hex: vector[1] as! String)
            let nIn = vector[2] as! NSNumber
            let nHashType = vector[3] as! NSNumber
            let sigHashBuf = Data(hex: vector[4] as! String)

            let script = Script(data: scriptBuf)!

            let tx = Transaction.deserialize(txBuf)

            XCTAssertEqual(tx.serialized().hex, txBuf.hex)

            let sighashValue = nHashType.intValue
            let sighash = UInt32(truncatingIfNeeded: sighashValue)
            let sighashType = SighashType(i: sighashValue)

            let hash = TransactionInputSigner.signatureHash(tx: tx, signatureVersion: .legacy, sighashType: sighashType, nIn: Int(truncating: nIn), subScript: script, value: 0)

            XCTAssertEqual(hash.hex, sigHashBuf.hex)
        }

    }

    

}
