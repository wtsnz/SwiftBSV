//
//  Script+Chunks.swift
//  SwiftBSV
//
//  Created by Will Townsend on 2020-10-20.
//  Copyright © 2020 Will Townsend. All rights reserved.
//

import Foundation

public struct Chunk: Equatable {
    public let buffer: Data?
    public let len: Int?
    public let opCodeNum: UInt8
}

// MARK: -

public struct ChunkHelpers {

    public static func scriptDataFromString(_ string: String) -> Data {
        let chunks = chunksFromString(string)
        return chunksToBuffer(chunks)
    }

    // MARK: - Conversions

    /// Input the script from the script string format used in bitcoind data tests
    public static func chunksFromAsmString(_ string: String) -> [Chunk] {
        var chunks: [Chunk] = []
        let tokens = string.components(separatedBy: " ")

        var i = 0

        while i < tokens.count {
            let token = tokens[i]

            var opCode: OpCode? = nil
            var opCodeNum: UInt8? = nil

            opCode = OpCodeFactory.get(with: token)
            opCodeNum = opCode?.value

            // we start with two special cases, 0 and -1, which are handled specially in
            // toASM. see chunksToAsmString.
            if token == "0" {
                opCodeNum = 0
                chunks.append(
                    Chunk(
                        buffer: nil,
                        len: nil,
                        opCodeNum: opCodeNum!
                    )
                )
                i = i + 1
            } else if token == "-1" {
                opCodeNum = OpCode.OP_1NEGATE.value
                chunks.append(
                    Chunk(
                        buffer: nil,
                        len: nil,
                        opCodeNum: opCodeNum!
                    )
                )
                i = i + 1
            } else if opCode == nil {
                let hex = tokens[i]
                let buf = Data(hex: hex)

                if buf.hex != hex {
                    fatalError("Invalid hex string in script")
                }

                let len = buf.count
                if len >= 0 && len < OpCode.OP_PUSHDATA1.value {
                    opCodeNum = UInt8(len)
                } else if len < Int(pow(Double(2), Double(8))) {
                    opCodeNum = OpCode.OP_PUSHDATA1.value
                } else if len < Int(pow(Double(2), Double(16))) {
                    opCodeNum = OpCode.OP_PUSHDATA2.value
                } else if len < Int(pow(Double(2), Double(32))) {
                    opCodeNum = OpCode.OP_PUSHDATA4.value
                } else {
                    fatalError("Too much data!")
                }

                chunks.append(
                    Chunk(
                        buffer: buf,
                        len: buf.count,
                        opCodeNum: opCodeNum!
                    )
                )

                i = i + 1
            } else {
                chunks.append(
                    Chunk(
                        buffer: nil,
                        len: nil,
                        opCodeNum: opCodeNum!
                    )
                )
                i = i + 1
            }
        }

        return chunks
    }

    public static func chunksToAsmString(_ chunks: [Chunk]) -> String {

        func chunkToString(_ chunk: Chunk) -> String {
            let opCodeNum = chunk.opCodeNum
            var string = ""

            if let buffer = chunk.buffer, let length = chunk.len {
                if length > 0 {
                    string = string + " " + buffer.hex
                }
            } else {
                // No  Data Chunk
                if let opCode = OpCodeFactory.get(with: opCodeNum) {
                    if opCode.value == 0 {
                        // OP_0 to "0"
                        string = string + " 0"
                    } else if opCode.value == 79 {
                        // OP_1NEGATE to "-1"
                        string = string + " -1"
                    } else {
                        string = string + " " + opCode.name
                    }
                } else {
                    var numString = String(opCodeNum, radix: 16)
                    if numString.count % 2 != 0 {
                        numString = "0" + numString
                    }
                    string = string + " " + numString
                }
            }
            return string
        }

        var string = ""
        for chunk in chunks {
            string += chunkToString(chunk)
        }
        return String(string.dropFirst())
    }

    /// Script from the script string format used in bitcoind data tests
    public static func bitcoindStringToBuffer(_ string: String) -> Data {
        var data = Data()
        let tokens = string.split(separator: " ").map { String($0) }

        for token in tokens {
            if token == "" {
                continue;
            }

            if token.starts(with: "0x") {
                let hex = String(token.dropFirst(2))
                data += Data(hex: hex)
            } else if token.starts(with: "'") {
                let string = String(token.dropFirst().dropLast())
                let cbuf = string.data(using: .utf8)!
                let chunk = chunkForBuffer(cbuf)
                let d = chunksToBuffer([chunk])
                data += d
            } else if let opCode = OpCodeFactory.get(with: "OP_" + token) {
                data += opCode.value
            } else if let number = UInt8(token), let opCode = OpCodeFactory.get(with: number) {
                data += opCode.value
            } else if let bignum = Int(token, radix: 10) {
                let bn = BInt(bignum)
                let chunks = chunksForBigInt(bn)
                let d = chunksToBuffer(chunks)
                data += d
            }
        }

        return data
    }

    /// Output the script to the script string format used in bitcoind data tests.
    public static func bitcoindStringFromChunks(_ chunks: [Chunk]) -> String {
        var string = ""
        for chunk in chunks {
            if let buffer = chunk.buffer {
                let encoded = chunksToBuffer([chunk])
                string = string + " " + "0x" + encoded.hex
            } else if let opCode = OpCodeFactory.get(with: chunk.opCodeNum) {
                string = string + " " + String(opCode.name.dropFirst(3)) // Drop the "OP_"
            } else {
                string = string + " " + "0x" + String(chunk.opCodeNum, radix: 16)
            }
        }
        return String(string.dropFirst())
    }

    public static func chunksFromString(_ string: String) -> [Chunk] {
        if string.count == 0 {
            return []
        }

        let tokens = string.split(separator: " ")
        var chunks: [Chunk] = []

        var i = 0
        while (i < tokens.count) {
            let token = String(tokens[i])

            let opCodeNum: UInt8? = OpCodeFactory.get(with: token)?.value

            if opCodeNum == nil {
                if let number = UInt8(token, radix: 10) {
                    if number > 0 && number < OpCode.OP_PUSHDATA1.value {
                        let string = String(String(tokens[i + 1]).dropFirst(2))
                        let data = Data(hex: string)

                        chunks.append(
                            Chunk(
                                buffer: data,
                                len: Int(number),
                                opCodeNum: number
                            )
                        )
                        i = i + 2
                    } else if number == 0 {
                        chunks.append(
                            Chunk(
                                buffer: nil,
                                len: nil,
                                opCodeNum: number
                            )
                        )
                        i = i + 1
                    } else {
                        fatalError("invalid")
                    }

                } else {
                    fatalError("invalid")
                }
            }
            else if (opCodeNum == OpCode.OP_PUSHDATA1.value || opCodeNum == OpCode.OP_PUSHDATA2.value || opCodeNum == OpCode.OP_PUSHDATA4.value) {

                var string = String(tokens[i + 2])

                if !string.starts(with: "0x") {
                    fatalError("Pushdata must start with 0x")
                }

                string = String(string.dropFirst(2))
                let data = Data(hex: string)

                let num = Int(tokens[i + 1], radix: 10)!
                chunks.append(
                    Chunk(
                        buffer: data,
                        len: num,
                        opCodeNum: opCodeNum!
                    )
                )

                i = i + 3

            } else {
                chunks.append(
                    Chunk(
                        buffer: nil,
                        len: nil,
                        opCodeNum: opCodeNum!
                    )
                )
                i = i + 1
            }

        }
        return chunks
    }

    public static func chunksFromBuffer(_ buffer: Data) -> [Chunk] {
        var chunks: [Chunk] = []

        let br = ByteStream(buffer)

        while (br.availableBytes > 0) {
            let opCodeNum = br.read(UInt8.self)

            var len = 0
            var buf = Data()

            if opCodeNum > 0 && opCodeNum < OpCode.OP_PUSHDATA1.value {
                len = Int(opCodeNum)
                let data = br.read(Data.self, count: len)
                chunks.append(
                    Chunk(
                        buffer: data,
                        len: len,
                        opCodeNum: opCodeNum
                    )
                )
            } else if opCodeNum == OpCode.OP_PUSHDATA1.value {
                len = Int(br.read(UInt8.self))

                buf = br.read(Data.self, count: len)
                chunks.append(
                    Chunk(
                        buffer: buf,
                        len: len,
                        opCodeNum: opCodeNum
                    )
                )
            } else if opCodeNum == OpCode.OP_PUSHDATA2.value {
                len = Int(br.read(UInt16.self))
                buf = br.read(Data.self, count: len)
                chunks.append(
                    Chunk(
                        buffer: buf,
                        len: len,
                        opCodeNum: opCodeNum
                    )
                )
            } else if opCodeNum == OpCode.OP_PUSHDATA4.value {
                len = Int(br.read(UInt32.self))
                buf = br.read(Data.self, count: len)
                chunks.append(
                    Chunk(
                        buffer: buf,
                        len: len,
                        opCodeNum: opCodeNum
                    )
                )
            } else {
                chunks.append(
                    Chunk(
                        buffer: nil,
                        len: nil,
                        opCodeNum: opCodeNum
                    )
                )
            }


        }

        return chunks

    }

    public static func chunksToBuffer(_ chunks: [Chunk]) -> Data {
        var buffer = Data()
        for chunk in chunks {
            buffer += chunk.opCodeNum
            if let data = chunk.buffer {
                if (chunk.opCodeNum < OpCode.OP_PUSHDATA1.value) {
                    buffer += data
                } else if (chunk.opCodeNum == OpCode.OP_PUSHDATA1.value) {
                    buffer += UInt8(data.count)
                    buffer += data
                } else if (chunk.opCodeNum == OpCode.OP_PUSHDATA2.value) {
                    buffer += UInt16(data.count)
                    buffer += data
                } else if (chunk.opCodeNum == OpCode.OP_PUSHDATA4.value) {
                    buffer += UInt32(data.count)
                    buffer += data
                }
            }
        }
        return buffer
    }

    public static func chunksToString(_ chunks: [Chunk]) -> String {
        var string = ""
        for chunk in chunks {

            if let data = chunk.buffer, let length = chunk.len {

                if (chunk.opCodeNum == OpCode.OP_PUSHDATA1.value || chunk.opCodeNum == OpCode.OP_PUSHDATA2.value || chunk.opCodeNum == OpCode.OP_PUSHDATA4.value) {
                    string = string + " " + OpCodeFactory.get(with: chunk.opCodeNum)!.name
                }

                string = string + " " + String(length)
                string = string + " " + "0x" + data.hex

            } else {

                if let opCode = OpCodeFactory.get(with: chunk.opCodeNum) {
                    string = string + " " + opCode.name
                } else {
                    string = string + " " + "0x" + String(chunk.opCodeNum, radix: 16)
                }

            }
        }
        return String(string.dropFirst())
    }

    // MARK: - Private

    private static func chunksForBigInt(_ bn: BInt) -> [Chunk] {
        var chunks: [Chunk] = []
        if bn == 0 {
            chunks.append(
                Chunk(
                    buffer: nil,
                    len: nil,
                    opCodeNum: OpCode.OP_0.value
                )
            )
        } else if bn == -1 {
            chunks.append(
                Chunk(
                    buffer: nil,
                    len: nil,
                    opCodeNum: OpCode.OP_1NEGATE.value
                )
            )
        } else if (bn >= 1 && bn <= 16) {
            // OP_1 to OP_16
            chunks.append(
                Chunk(
                    buffer: nil,
                    len: nil,
                    opCodeNum: UInt8(bn.asInt()!) + OpCode.OP_1.value - 1
                )
            )
        } else {
            let buf = bn.toSm(endian: "little")
            chunks.append(chunkForBuffer(buf))
        }

        return chunks
    }

    private static func chunkForBuffer(_ buffer: Data) -> Chunk {
        var opCodeNum: UInt8
        let len = buffer.count

        if buffer.count > 0 && buffer.count < OpCode.OP_PUSHDATA1.value {
            opCodeNum = UInt8(buffer.count)
        } else if buffer.count == 0 {
            opCodeNum = OpCode.OP_0.value
        } else if buffer.count < Int(pow(Double(2), Double(8))) {
            opCodeNum = OpCode.OP_PUSHDATA1.value
        } else if buffer.count < Int(pow(Double(2), Double(16))) {
            opCodeNum = OpCode.OP_PUSHDATA2.value
        } else if buffer.count < Int(pow(Double(2), Double(32))) {
            opCodeNum = OpCode.OP_PUSHDATA4.value
        } else {
            fatalError("Too much data!")
        }
        return Chunk(
            buffer: buffer,
            len: len,
            opCodeNum: opCodeNum
        )
    }

}

extension Script {
    public convenience init?(string: String) {
        let chunks = ChunkHelpers.chunksFromString(string)
        let buffer = ChunkHelpers.chunksToBuffer(chunks)
        self.init(hex: buffer.hex)
    }
}
