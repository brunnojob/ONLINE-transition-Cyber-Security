import Foundation
import CryptoKit

enum GuardError: Error {
    case invalidEnvelope
}

func sign(key: Data, payload: Data, origin: String) throws -> String {
    guard let text = String(data: payload, encoding: .ascii) else { throw GuardError.invalidEnvelope }
    let fields = text.components(separatedBy: "\n")
    guard fields.count == 10, fields[0] == "GUARD-V1", fields[9] == origin,
          let expires = TimeInterval(fields[8]), expires > Date().timeIntervalSince1970 else {
        throw GuardError.invalidEnvelope
    }
    let privateKey = try P256.Signing.PrivateKey(derRepresentation: key)
    return try privateKey.signature(for: payload).derRepresentation.base64EncodedString()
}

let args = CommandLine.arguments
if args.count != 4 { throw GuardError.invalidEnvelope }
print(try sign(key: Data(contentsOf: URL(fileURLWithPath: args[1])), payload: Data(contentsOf: URL(fileURLWithPath: args[2])), origin: args[3]))
