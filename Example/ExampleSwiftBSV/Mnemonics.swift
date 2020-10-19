//
//  Mnemonics.swift
//  Example
//
//  Created by Will Townsend on 2020-04-20.
//

import SwiftUI
import SwiftBSV

class MnemonicsViewModel: ObservableObject {

    @Published var mnemonicString: String = ""
    @Published var xprivKey: String = ""
    @Published var address: String = ""

    @Published var transactionASM: String = ""

    private var strength: Bip39.Strength = .high


    init() {
        generateMnemonic()
    }

    func generateMnemonic(strength: Bip39.Strength? = nil) {

        if let strength = strength {
            self.strength = strength
        }

        let mnemonicString = Bip39.create(strength: self.strength)
        self.setMnemonic(mnemonicString)
    }

    func setMnemonic(_ string: String) {
        self.mnemonicString = string

        let seed = Bip39.createSeed(mnemonic: mnemonicString)

        let key = Bip32(seed: seed)

        xprivKey = key.toString()

//        let privateKey = PrivateKey(seed: seed)

        self.address = Address(key).toString()

    }

}

struct Mnemonics: View {

    @ObservedObject var viewModel = MnemonicsViewModel()

    @State var strength: Int = 0

    init() {

    }

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading) {

                Text("Mnemonics (BIP-39)")
                    .font(.headline)


                Button("Generate") {
                    self.viewModel.generateMnemonic()
                }

                Picker("Strength", selection: Binding<Int>(
                    get: { self.strength },
                    set: { new in
                        self.strength = new
                        self.viewModel.generateMnemonic(strength: new == 0 ? .normal : .high)
                    }
                )) {
                    Text("Normal")
                        .tag(0)
                    Text("High")
                        .tag(1)
                }
                .pickerStyle(SegmentedPickerStyle())

                TextField("Mnemonic", text: Binding<String>(
                    get: { self.viewModel.mnemonicString },
                    set: { new in self.viewModel.setMnemonic(new) }
                ), onEditingChanged: { _ in

                })

                TextField("Address", text: Binding<String>(
                    get: { self.viewModel.xprivKey },
                    set: { new in return }
                ))

                TextField("Address", text: Binding<String>(
                    get: { self.viewModel.address },
                    set: { new in return }
                ))
            }
            .padding()
        }
    }
}

struct Mnemonics_Previews: PreviewProvider {
    static var previews: some View {
        Mnemonics()
    }
}
