//
//  ContentView.swift
//  ExampleSwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//

import SwiftUI
import SwiftBSV

struct ContentView: View {

    let pk: PrivateKey = PrivateKey()

    var body: some View {
        Text("Hello, World! \(pk.toWif())")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}


struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
