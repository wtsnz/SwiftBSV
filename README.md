# SwiftBSV

A library to help you create Bitcoin transactions in Swift.

The goal is to mimic the https://github.com/moneybutton/bsv/ lib as close as possible. I've used multiple existing open source Bitcoin Swift libraries as a starting point. This project is in active development and will continue to change significantly.

Todo:

- [x] BInt (Big Number)
- [x] Base58Check
- [x] Point (Elliptic Curve Points)
- [x] PublicKeys
- [x] PrivateKeys
- [x] Bip39 (Mnemonic)
- [x] Bip32 (HD Wallets)
- [x] TxBuilder
- [ ] more...


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

## Usage Examples

### BIP-39: Mnemonic Seeds

```swift
let mnemonic = Bip39.create()
let seed = Bip39.createSeed(mnemonic: mnemonic)
let rootKey = Bip32(seed: seed, network: .mainnet)

print(rootKey.address)

// 1C8eycEadLHZZfRkchqTC3e72fRNNfbXs3
```

### Bitcoin Signed Messages

#### Sign a message

```swift
let message = "hello!"
let privateKey = PrivateKey()
let address = privateKey.address
let sigString = BitcoinSignedMessage.sign(message: message, privateKey: privateKey)
print(sigString)

// H5wZz9N2+O8oHCMfZBE5nbeM6dr2ZwpD6cKhC0q1lPi/A1t9KV5VO0vTL2kRg8Hg7XSmZl1cviZFj4TkfLAGT9E=
```

#### Verify a message

```swift
let message = "hello!"
let address = Address(fromString: "1D7ZaBLeT3FFr1mcKAWorZHdE18kEVvuaY")!

let sigString = "IOsRLk8/CBpLvOecpV0kh4ajjgpUH04T3kkJRPJng5kMOe3Az0gwGx2n8dHyooGykrqB6SuMCPtahZ5EN/TcZzg="

let valid = BitcoinSignedMessage.verify(message: message, signature: sigString, address: address)
print(valid)

// true
```

### Create a Transaction

```swift
let privateKey = PrivateKey(data: wallet.privateKey)
let publicKey = privateKey.publicKey
let address = publicKey.address

let txb = TxBuilder()
    .setFeePerKb(500)
    .setChangeAddress(address)

// Add inputs to the transaction
var numberOfInputs = 0
for utxo in utxos {
    let txHashBuf = Data(Data(hex: utxo.txId).reversed())
    let txOut = TransactionOutput(
        value: utxo.satoshis,
        lockingScript: Data(hex: utxo.script)
    )

    txb.inputFromPubKeyHash(
        txHashBuffer: txHashBuf,
        txOutNum: utxo.outputIndex,
        txOut: txOut,
        pubKey: publicKey
    )

    numberOfInputs = numberOfInputs + 1
}

// Add a data output

var script = try! Script().append(.OP_FALSE).append(.OP_RETURN).appendData("hello, world!".data(using: .utf8)!)

txb.outputToScript(
    value: 0,
    script: script
)

// Add an output to another Address (pay-to-pubkey-hash)
let value = UInt64(payee.amount * 100_000_000)
txb.outputToAddress(value: value, address: Address(fromString: payee.to)!)

// Build, using all the inputs

try! txb.build(useAllInputs: true)

// Finally sign the built transaction
for input in 0..<numberOfInputs {
    txb.signInTx(nIn: input, privateKey: privateKey)
}


// Do something with the signed transaction!
txb.transaction

```

## Author

Will Townsend


## License

SwiftBSV is available under the MIT license. See [the LICENSE file](LICENCE.md) for more information.

## Thanks to

This project is a mashup of a bunch of open source projects, and many original contributions and wouldn't have been possible without the following projects:

- https://github.com/KevinVitale/WalletKit
- https://github.com/yuzushioh/HDWalletKit
- https://github.com/yenom/BitcoinKit
- https://github.com/moneybutton/bsv
