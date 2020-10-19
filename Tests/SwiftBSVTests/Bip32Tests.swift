//
//  Bip32Tests.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-17.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import XCTest
@testable import SwiftBSV

class Bip32Tests: XCTestCase {

    func no_testInit() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

        let buffer = Base58Check.decode(xprv)!
        let bip32 = Bip32(buffer)!

        XCTAssertEqual(bip32.toString(), xprv)
        XCTAssertEqual(bip32.toPublic().toString(), xpub)
    }

    func test() {
        let seed = "patrol wide sure scale grant school donate enact assume mask hint lottery" //Bip39.create()
        let seedData = Bip39.createSeed(mnemonic: seed)

        XCTAssertEqual(
            seedData.hex,
            "c9dd17fff727f7d85fd4cef05350e0021b3581b235b9517b43deaa723bec2230681dc8c3ec94ca9178a860be6088e8f43322ace55603ea651d64480ec293611a"
        )

        let bip32 = Bip32(seed: seedData)

//        dump(bip32.wifCompressed())
//        dump(bip32.wifUncompressed())

        XCTAssertEqual(
            bip32.toString(),
            "xprv9s21ZrQH143K4A3XFxYqckr3NJdtuTYYbZCUxwkuRpJCguxYCugtZLx1vABD4CbekwnQPvRzhagpGgX3WKbViA5QS6AYt6dgrLnQKUXx4UM"
        )
        dump(bip32.toString())

//        dump(bip32.publicKey.address)

//        let zer0 = bip32.derived(at: .hardened(0))
//        dump(bip32.derived(at: .hardened(0)).toString())
//        dump(bip32.derived(at: .notHardened(0)).toString())

//        XCTAssertEqual(
//            zer0.extended(),
//            "xprv9vcT46GVjV1WVs5jhtyQmBeqXhWVKdj9Hh9sqvHwVYLzrpiHZXjdxi2LDRnCEa8j8tL9ZuC7RL6WSfdSgpy7DCgrU91q9mFvkyQLs1tNKJV"
//        )

//        dump(bip32.publicKey.address)

        let vector1master = "000102030405060708090a0b0c0d0e0f"
        let vector1mPublic = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        let vector1mPrivate = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

        let vector1m0hPublic = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        let vector1m0hPrivate = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        let vector1m0h1Public = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        let vector1m0h1Private = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
//        let vector1m0h12hPublic = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
//        let vector1m0h12hPrivate = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
//        let vector1m0h12h2Public = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
//        let vector1m0h12h2Private = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
//        let vector1m0h12h21000000000Public = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
//        let vector1m0h12h21000000000Private = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        let m = Bip32(seed: Data(hex: vector1master))
        XCTAssertEqual(m.toString(), vector1mPrivate)

        let pub = m.toPublic()
        XCTAssertEqual(pub.toString(), vector1mPublic)

        let m0h = m.derived(at: .hardened(0))!

        print(m.derived(at: .hardened(0))!.toString())
        print(m.derived(at: .notHardened(0))!.toString())

        XCTAssertEqual(vector1m0hPrivate, m.derived(at: .hardened(0))!.toString())
        XCTAssertEqual(vector1m0hPublic,  m.derived(at: .hardened(0))!.toPublic().toString())

        //
//        let m0h1 = m0h.derived(at: .notHardened(1))!
//        XCTAssertEqual(m0h1.toString(), vector1m0h1Private)
//        XCTAssertEqual(m0h1.toPublic().toString(), vector1m0h1Public)
    }

    func testWordlistLength() {
        XCTAssertEqual(WordList.english.words.count, 2048)
        XCTAssertEqual(WordList.french.words.count, 2048)
        XCTAssertEqual(WordList.italian.words.count, 2048)
        XCTAssertEqual(WordList.japanese.words.count, 2048)
        XCTAssertEqual(WordList.korean.words.count, 2048)
    }

    func testCommunityDerrivedTestVector() {
        // There was a bug in Copay and bip32jp about deriving addresses with bip39
        // and bip44. This confirms we are handling the situation correctly and
        // derive the correct value.
        //
        // More information here:
        // https://github.com/iancoleman/bip39/issues/58

        let seed = Bip39.createSeed(mnemonic: "fruit wave dwarf banana earth journey tattoo true farm silk olive fence", withPassphrase: "banana")

//        let ss = PrivateKey(seed: seed)
//
//        dump(ss.wifCompressed())
//        dump(ss.wifUncompressed())
//
//        let derrived = ss
//            .derived(at: .hardened(44))
//            .derived(at: .hardened(0))
//            .derived(at: .hardened(0))
//            .derived(at: .notHardened(0))
//            .derived(at: .notHardened(0))

//        XCTAssertEqual(derrived.publicKey.address, "17rxURoF96VhmkcEGCj5LNQkmN9HVhWb7F")
    }

}
