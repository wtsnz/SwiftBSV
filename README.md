# SwiftBSV

A library to help you create Bitcoin transactions in Swift.

The goal is to mimic the https://github.com/moneybutton/bsv/ lib as close as possible. I've used multiple existing open source Bitcoin Swift libraries as a starting point. This project is in active development and will continue to change significantly.

Todo:

- [x] BInt (Big Number)
- [x] Base58Check
- [ ] Point (Elliptic Curve Points)
- [ ] PublicKeys
- [ ] PrivateKeys
- [ ] Bip39 (Mnemonic)
- [ ] Bip32 (HD Wallets)



## Usage Examples

### BIP-39: Mnemonic Seeds

```swift
let mnemonicString = Bip39.create(strength: strength)
let seed = Bip39.createSeed(mnemonic: mnemonicString)
let privateKey = PrivateKey(seed: seed)
```


## Installation

Add this to your project using Swift Package Manager. In Xcode that is simply: File > Swift Packages > Add Package Dependency... and you're done. Alternative installations options are shown below for legacy projects.

### CocoaPods

If you are already using [CocoaPods](http://cocoapods.org), just add 'SwiftBSV' to your `Podfile` then run `pod install`.

### Carthage

If you are already using [Carthage](https://github.com/Carthage/Carthage), just add to your `Cartfile`:

```ogdl
github "wtsnz/SwiftBSV" ~> 0.1
```

Then run `carthage update` to build the framework and drag the built `SwiftBSV`.framework into your Xcode project.


## Author

Will Townsend


## License

SwiftBSV is available under the MIT license. See [the LICENSE file](LICENSE) for more information.

## Thanks to

This project is a mashup of a bunch of open source projects and wouldn't have been possible without these:

- https://github.com/KevinVitale/WalletKit
- https://github.com/yuzushioh/HDWalletKit
- https://github.com/yenom/BitcoinKit
- https://github.com/moneybutton/bsv
