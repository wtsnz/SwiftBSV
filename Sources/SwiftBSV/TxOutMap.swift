//
//  TxOutmap.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

/**
 * Transaction Output Map
 * ======================
 *
 * A map from a transaction hash and output number to that particular output.
 * Note that the map is from the transaction *hash*, which is the value that
 * occurs in the blockchain, not the id, which is the reverse of the hash. The
 * TxOutMap is necessary when signing a transction to get the script and value
 * of that output which is plugged into the sighash algorithm.
 */
class TxOutMap {

    private var dictionary = [String: TransactionOutput]()

    /// Set the output index for the input transaction id + outpoint index
    func set(txHashBuf: Data, txOutNum: UInt32, txOut: TransactionOutput) {
        let label = txHashBuf.hex + ":" + String(txOutNum)
        dictionary[label] = txOut
    }

    /// Get the output index for the input transaction id + outpoint index
    func get(txHashBuf: Data, txOutNum: UInt32) -> TransactionOutput? {
        let label = txHashBuf.hex + ":" + String(txOutNum)
        return dictionary[label]
    }

    func setTx(tx: Transaction) {
        let txId = tx.txHash.hex
        tx.outputs.enumerated().forEach({ (index, txOut) in
            let label = txId + ":" + String(index)
            dictionary[label] = txOut
        })
    }

}
