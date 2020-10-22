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

    func testTransction() {

        let txIdHex = "8c9aa966d35bfeaf031409e0001b90ccdafd8d859799eb945a3c515b8260bcf2"

        let txHex = "01000000013349f331edd46ff1a4a09c0ec6ca074d2e25ecefeba6fdd1a331c06f98592bee0100000023002102c8b519fa21f8205a7086378a3806a312a3e3c918899cb18c2c8a775b4a5be462ffffffff0210270000000000001976a91463cb92e6d497e36390c60ff3b1bac0c97636738388ac48058900000000001976a91463cb92e6d497e36390c60ff3b1bac0c97636738388ac00000000"

//        let txHex = "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
        let txBuf = Data(hex: txHex)

        let tx = Transaction.deserialize(txBuf)

        dump(tx)

        let helper = BSVSignatureHashHelper(hashType: SighashType.BSV.ALL)

        let sig = helper.createSignatureHash(of: tx, for: tx.outputs[0], inputIndex: Int(0))

        let sig2 = helper.createSignatureHash(of: tx, for: tx.outputs[1], inputIndex: Int(0))

        print(sig.hex)


        // Should be serializable
        XCTAssertEqual(tx.serialized().hex, txHex)

        // Should calculate the txId
        XCTAssertEqual(tx.txID, txIdHex)




    }

    func testVectors() {
//        let txValidJson = TestHelpers.jsonResource(pathComponents: [
//            "vectors",
//            "bitcoind",
//            "tx_valid.json"
//        ])
//
//        let txValidJsonArray = txValidJson as! NSArray
//
//        txValidJsonArray.forEach { vector in
//            let vector = vector as! NSArray
//
//            if vector.count == 1 {
//                return
//            }
//
//            let txBuf = Data(hex: vector[1] as! String)
//            let tx = Transaction.deserialize(txBuf)
//
//            XCTAssertEqual(tx.serialized().hex, txBuf.hex)
//        }
//
//        // --- Tx Invalid
//
//        let txInvalidJson = TestHelpers.jsonResource(pathComponents: [
//            "vectors",
//            "bitcoind",
//            "tx_invalid.json"
//        ])
//
//        let txInvalidJsonArray = txInvalidJson as! NSArray
//
//        txInvalidJsonArray.forEach { vector in
//            let vector = vector as! NSArray
//
//            if vector.count == 1 {
//                return
//            }
//
//            let txBuf = Data(hex: vector[1] as! String)
//            let tx = Transaction.deserialize(txBuf)
//
//            XCTAssertEqual(tx.serialized().hex, txBuf.hex)
//        }

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

            let tx = Transaction.deserialize(txBuf)

            let utxo = tx.inputs.first(where: { $0.signatureScript.hex == scriptBuf.hex })

            XCTAssertEqual(tx.serialized().hex, txBuf.hex)

            let helper = BSVSignatureHashHelper(hashType: SighashType.BSV.ALL)

            helper.createSignatureHash(of: tx, for: tx.outputs[0], inputIndex: Int(nIn))

            print("")
        }

    }

    

}
