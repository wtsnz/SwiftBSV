//
//  Data+Random.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 20.08.18.
//  Copyright © 2018 Essentia. All rights reserved.
//

import Foundation

extension Data {

    /// Securely generate random bytes of length.
    static func randomBytes(length: Int) -> Data {
        var bytes = Data(count: length)
        _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        return bytes
    }
}
