//
//  DataConvertable.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//  Copyright © 2020 wtsnz. All rights reserved.
//

import Foundation

protocol DataConvertable {
    static func +(lhs: Data, rhs: Self) -> Data
    static func +=(lhs: inout Data, rhs: Self)
}

extension DataConvertable {
    static func +(lhs: Data, rhs: Self) -> Data {
        var value = rhs
        let data = Data(buffer: UnsafeBufferPointer(start: &value, count: 1))
        return lhs + data
    }
    
    static func +=(lhs: inout Data, rhs: Self) {
        lhs = lhs + rhs
    }
}

extension UInt8: DataConvertable {}
extension UInt32: DataConvertable {}

