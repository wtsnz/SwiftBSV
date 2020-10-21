//
//  TestHelpers.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-20.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

struct TestHelpers {

    static func jsonResource(pathComponents: [String]) -> Any {
        let thisSourceFile = URL(fileURLWithPath: #file)
        let testsDirectory = thisSourceFile
            .deletingLastPathComponent()

        let resourcesURL = testsDirectory.appendingPathComponent("Resources")

        let url = pathComponents.reduce(resourcesURL) { (result, component) in
            return result.appendingPathComponent(component)
        }

        let json = try! JSONSerialization.jsonObject(
            with: try! Data(contentsOf: url),
            options: []
        )

        return json
    }

}
