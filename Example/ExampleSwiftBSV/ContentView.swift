//
//  ContentView.swift
//  ExampleSwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//

import SwiftUI
import SwiftBSV

struct DetailView: View {
    let text: String

    var body: some View {
        Text(text)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ContentView: View {

    @State private var selection: String?

    var body: some View {
        NavigationView {
            List(selection: $selection) {
                Section(header: Text("Mnemonics")) {
                    NavigationLink(destination: Mnemonics()) {
                        Text("Mnemonics (BIP-39)")
                    }
                }
            }
            .listStyle(SidebarListStyle())

            DetailView(text: "Make a selection")
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
