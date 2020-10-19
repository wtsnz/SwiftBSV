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

    func testFromXpubKey() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

        let publicKey = Bip32(string: xpub)

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

        print(m.derived(at: .hardened(0))!.toString())
        print(m.derived(at: .notHardened(0))!.toString())

        XCTAssertEqual(vector1m0hPrivate, m.derived(at: .hardened(0))!.toString())
        XCTAssertEqual(vector1m0hPublic, m.derived(at: .hardened(0))!.toPublic().toString())

//        Bip32.init(

        let test = Bip32(string: vector1mPrivate)
        XCTAssertEqual(vector1mPrivate, test?.toString())


        let m0h1 = m.derivedKey(path: "m/0'/1")!
        XCTAssertEqual(m0h1.toString(), vector1m0h1Private)
        XCTAssertEqual(m0h1.toPublic().toString(), vector1m0h1Public)

        let m0h = m.derivedKey(path: "m/0'")!
        XCTAssertEqual(m0h.toString(), "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        XCTAssertEqual(m0h.toPublic().toString(), "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

//        let m0h1 = m.derivedKey(path: "m/0'/1")!
        XCTAssertEqual(m0h1.toString(), "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        XCTAssertEqual(m0h1.toPublic().toString(), "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

        let key = m.derivedKey(path: "m/0")!
        XCTAssertEqual(key.toString(), "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R")
        XCTAssertEqual(key.toPublic().toString(), "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1")

        let keym1 = m.derivedKey(path: "m/1")!
        XCTAssertEqual(keym1.toString(), "xprv9uHRZZhbkedL4yTpidDvuVfrdUkTbhDHviERRBkbzbNDZeMjWzqzKAdxWhzftGDSxDmBdakjqHiZJbkwiaTEXJdjZAaAjMZEE3PMbMrPJih")
        XCTAssertEqual(keym1.toPublic().toString(), "xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq")

        let key2 = m.derivedKey(path: "m/0/0")!
        XCTAssertEqual(key2.toString(), "xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc")
        XCTAssertEqual(key2.toPublic().toString(), "xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj")

        let key3 = m.derivedKey(path: "m/0/0'")!
        XCTAssertEqual(key3.toString(), "xprv9ww7sMFVKxty8YzC4nKSgnUKNFM2uSybNoV24kC82UF9JJMgmZF61rNcd5J8M8d5DkxPLT79SgfSYwL6V8PRwNsgYYrRj2BM8eZ2nZEHrsi")
        XCTAssertEqual(key3.toPublic().toString(), "xpub6AvUGrnPALTGM34fAorT3vR3vHBXJuhSk2Qcs8bjaon8B6gqK6ZLZeh6UMqPaS6a4Q1fByzY74W5L8vB2XedwzhFVaiXW8ggTsuRBRm65ak")

        let key4 = m.derivedKey(path: "m/0/0'/0")!
        XCTAssertEqual(key4.toString(), "xprv9zBKtvK89AYadQAvEGN8ihoB6G84pB7rsmgo8p8NhkPXZr6uRScPUYNQoBHC7pYjxx1XfK92Fu5ioUg9PrEwUv3gv9SCmq5bp1R2YMHNa92")
        XCTAssertEqual(key4.toPublic().toString(), "xpub6DAgJRr1yY6sqtFPLHu95qjueHxZDdqiEzcPwCXzG5vWSeS3xyve2LgteUvFiHi4EEZoeQatG1uBWNF46vfEsjWG7MhGuAmoTSDKdKXojan")

        let key5 = m.derivedKey(path: "m/0'/1/2'/2/1000000000")!
        XCTAssertEqual(key5.toString(), "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        XCTAssertEqual(key5.toPublic().toString(), "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")


        print(key.toString())
        print("sdf")

        XCTAssertEqual(m.derivedKey(path: "m/0'/1")?.toString(), vector1m0h1Private)
        XCTAssertEqual(m.derivedKey(path: "m/0'/1")?.toPublic().toString(), vector1m0h1Public)


    }

    func testHDKey1() {
        // Test Vector 1
        /*
         Master (hex): 000102030405060708090a0b0c0d0e0f
         * [Chain m]
         * ext pub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
         * ext prv: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
         * [Chain m/0']
         * ext pub: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw
         * ext prv: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
         * [Chain m/0'/1]
         * ext pub: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
         * ext prv: xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs
         * [Chain m/0'/1/2']
         * ext pub: xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5
         * ext prv: xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM
         * [Chain m/0'/1/2'/2]
         * ext pub: xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV
         * ext prv: xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334
         * [Chain m/0'/1/2'/2/1000000000]
         * ext pub: xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy
         * ext prv: xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76
         */

        // Master: 000102030405060708090a0b0c0d0e0f
        let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")

        // m
        let privateKey = Bip32(seed: seed, network: .mainnet)
        XCTAssertEqual(privateKey.toPublic().toString(), "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        XCTAssertEqual(privateKey.toString(), "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")

        // m/0'
        let m0prv = privateKey.derived(at: .hardened(0))!
        XCTAssertEqual(m0prv.toPublic().toString(), "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
        XCTAssertEqual(m0prv.toString(), "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")

        // m/0'/1
        let m01prv = m0prv.derived(at: .notHardened(1))!
        XCTAssertEqual(m01prv.toPublic().toString(), "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
        XCTAssertEqual(m01prv.toString(), "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")

        // m/0'/1/2'
        let m012prv = m01prv.derived(at: .hardened(2))!
        XCTAssertEqual(m012prv.toPublic().toString(), "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")
        XCTAssertEqual(m012prv.toString(), "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")

        // m/0'/1/2'/2
        let m0122prv = m012prv.derived(at: .notHardened(2))!
        XCTAssertEqual(m0122prv.toPublic().toString(), "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
        XCTAssertEqual(m0122prv.toString(), "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")

        // m/0'/1/2'/2/1000000000
        let m01221000000000prv = m0122prv.derived(at: .notHardened(1000000000))!
        XCTAssertEqual(m01221000000000prv.toPublic().toString(), "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
        XCTAssertEqual(m01221000000000prv.toString(), "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
    }

    func testHDKey2() {
        // Test Vector 2
        /*
         Master (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
         * [Chain m]
         * ext pub: xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB
         * ext prv: xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
         * [Chain m/0]
         * ext pub: xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH
         * ext prv: xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt
         * [Chain m/0/2147483647']
         * ext pub: xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a
         * ext prv: xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9
         * [Chain m/0/2147483647'/1]
         * ext pub: xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon
         * ext prv: xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef
         * [Chain m/0/2147483647'/1/2147483646']
         * ext pub: xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL
         * ext prv: xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc
         * [Chain m/0/2147483647'/1/2147483646'/2]
         * ext pub: xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt
         * ext prv: xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j
         */

        // Master: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
        let seed = Data(hex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

        // m
        let privateKey = Bip32(seed: seed, network: .mainnet)
        XCTAssertEqual(privateKey.toPublic().toString(), "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")
        XCTAssertEqual(privateKey.toString(), "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")

        // m/0
        let m0prv = privateKey.derived(at: .notHardened(0))!
        XCTAssertEqual(m0prv.toPublic().toString(), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
        XCTAssertEqual(m0prv.toString(), "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")

        // m/0/2147483647'
        let m02147483647prv = m0prv.derived(at: .hardened(2147483647))!
        XCTAssertEqual(m02147483647prv.toPublic().toString(), "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")
        XCTAssertEqual(m02147483647prv.toString(), "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")

        // m/0/2147483647'/1
        let m021474836471prv = m02147483647prv.derived(at: .notHardened(1))!
        XCTAssertEqual(m021474836471prv.toPublic().toString(), "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")
        XCTAssertEqual(m021474836471prv.toString(), "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")

        // m/0/2147483647'/1/2147483646'
        let m0214748364712147483646prv = m021474836471prv.derived(at: .hardened(2147483646))!
        XCTAssertEqual(m0214748364712147483646prv.toPublic().toString(), "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")
        XCTAssertEqual(m0214748364712147483646prv.toString(), "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")

        // m/0/2147483647'/1/2147483646'/2
        let m02147483647121474836462prv = m0214748364712147483646prv.derived(at: .notHardened(2))!
        XCTAssertEqual(m02147483647121474836462prv.toPublic().toString(), "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
        XCTAssertEqual(m02147483647121474836462prv.toString(), "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
    }

    func testHDKey3() {
        // Test Vector 3
        // These vectors test for the retention of leading zeros. See bitpay/bitcore-lib#47 and iancoleman/bip39#58 for more information.

        // Master: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
        let seed = Data(hex: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")

        // m
        let privateKey = Bip32(seed: seed)
        XCTAssertEqual(privateKey.toPublic().toString(), "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")
        XCTAssertEqual(privateKey.toString(), "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")

        // m/0'
        let m0prv = privateKey.derived(at: .hardened(0))!
        XCTAssertEqual(m0prv.toPublic().toString(), "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")
        XCTAssertEqual(m0prv.toString(), "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
    }

    func testCommunityDerrivedTestVector() {

        let bip32 = Bip32(seed: Data(hex: "f27fd395d30d00f1c11b7551a93961ca41c0a78bce21e9a618e83a99cf74aec159139ef3ef078bc0038557b7cb689933d0806ce33571df78bc4397e7f9976ff2"))
//
        let derived = bip32
            .derived(at: .hardened(44))!
            .derived(at: .hardened(0))!
            .derived(at: .hardened(0))!
            .derived(at: .notHardened(1))!
            .derived(at: .notHardened(19))!

        let privateKey = PrivateKey(rawData: derived.privateKey!.data)

        XCTAssertEqual(privateKey.bn.data.count, 32)
        XCTAssertEqual(privateKey.bn.data.hex, "00f2c37dad54d1d2be57b06653ea655c6fd8eb3ca3f0b9671e036d50061d265b")
        XCTAssertEqual(privateKey.toWif(), "KwFZ6jFtuvBu7w4R4x4WpzQgSSYTHLEw8Pr2PUkWjADkHJUPNDVg")
        XCTAssertEqual(privateKey.publicKey.toDer().hex, "02a712f894d58baef44e4fbbc26ed6ca89487db1f17e944f9b45ca2ae666e99d72")

//        XCTAssertEqual(derrived.publicKey.address, "17rxURoF96VhmkcEGCj5LNQkmN9HVhWb7F")
    }

}
