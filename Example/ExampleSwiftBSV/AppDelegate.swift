//
//  AppDelegate.swift
//  ExampleSwiftBSV
//
//  Created by Will Townsend on 2020-10-18.
//

import Cocoa
import SwiftUI
import SwiftBSV

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    var window: NSWindow!


    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Create the SwiftUI view that provides the window contents.
        let contentView = ContentView()

        examples()

        // Create the window and set the content view.
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 300),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.center()
        window.setFrameAutosaveName("Main Window")
        window.contentView = NSHostingView(rootView: contentView)
        window.makeKeyAndOrderFront(nil)
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    func examples() {

        // Create a mnemonic

        let mnemonic = Bip39.create()
        let seed = Bip39.createSeed(mnemonic: mnemonic)
        let rootKey = Bip32(seed: seed, network: .mainnet)

        print(rootKey.address)

        do {
            let mnemonic = "patrol wide sure scale grant school donate enact assume mask hint lottery"
            let seed = Bip39.createSeed(mnemonic: mnemonic)

            let rootKey = Bip32(seed: seed)

            print(rootKey)

        }
    }


}

