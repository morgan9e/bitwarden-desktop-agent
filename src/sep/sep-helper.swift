import Foundation
import Security

let service = "com.bitwarden.agent"
let algo = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

func sepTag(_ label: String) -> Data {
    "\(service).sep.\(label)".data(using: .utf8)!
}

func getSEPKey(_ label: String) -> SecKey? {
    let q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: sepTag(label),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
    ]
    var ref: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &ref) == errSecSuccess ? (ref as! SecKey) : nil
}

func createSEPKey(_ label: String) -> SecKey {
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &err
    ) else {
        fatal("access control: \(err!.takeRetainedValue())")
    }

    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: sepTag(label),
            kSecAttrAccessControl as String: access,
        ] as [String: Any],
    ]

    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        fatal("create SEP key: \(err!.takeRetainedValue())")
    }
    return key
}

func removeSEPKey(_ label: String) {
    let q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: sepTag(label),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
    SecItemDelete(q as CFDictionary)
}

func storeBlob(_ label: String, _ data: Data) {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: label,
    ]
    SecItemDelete(q as CFDictionary)

    var add = q
    add[kSecValueData as String] = data
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

    let s = SecItemAdd(add as CFDictionary, nil)
    if s != errSecSuccess { fatal("store blob: \(s)") }
}

func loadBlob(_ label: String) -> Data? {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: label,
        kSecReturnData as String: true,
    ]
    var ref: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &ref) == errSecSuccess ? (ref as! Data) : nil
}

func removeBlob(_ label: String) {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: label,
    ]
    SecItemDelete(q as CFDictionary)
}

func hasBlob(_ label: String) -> Bool {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: label,
    ]
    return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
}

func encrypt(_ pubKey: SecKey, _ data: Data) -> Data {
    var err: Unmanaged<CFError>?
    guard let ct = SecKeyCreateEncryptedData(pubKey, algo, data as CFData, &err) else {
        fatal("encrypt: \(err!.takeRetainedValue())")
    }
    return ct as Data
}

func decrypt(_ privKey: SecKey, _ data: Data) -> Data {
    var err: Unmanaged<CFError>?
    guard let pt = SecKeyCreateDecryptedData(privKey, algo, data as CFData, &err) else {
        fatal("decrypt: \(err!.takeRetainedValue())")
    }
    return pt as Data
}

func readStdin() -> Data {
    var buf = Data()
    while let line = readLine(strippingNewline: false) {
        buf.append(line.data(using: .utf8)!)
    }
    let trimmed = String(data: buf, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let decoded = Data(base64Encoded: trimmed) else {
        fatal("invalid base64 on stdin")
    }
    return decoded
}

func fatal(_ msg: String) -> Never {
    FileHandle.standardError.write("sep-helper: \(msg)\n".data(using: .utf8)!)
    exit(1)
}

func usage() -> Never {
    FileHandle.standardError.write("usage: sep-helper <store|load|remove|has> <label>\n".data(using: .utf8)!)
    exit(2)
}

let args = CommandLine.arguments
if args.count < 3 { usage() }
let cmd = args[1]
let label = args[2]

switch cmd {
case "store":
    let data = readStdin()
    let privKey = getSEPKey(label) ?? createSEPKey(label)
    guard let pubKey = SecKeyCopyPublicKey(privKey) else { fatal("no public key") }
    let ct = encrypt(pubKey, data)
    storeBlob(label, ct)

case "load":
    guard let privKey = getSEPKey(label) else { fatal("no SEP key for \(label)") }
    guard let ct = loadBlob(label) else { fatal("no data for \(label)") }
    let pt = decrypt(privKey, ct)
    let b64 = pt.base64EncodedString()
    print(b64)

case "remove":
    removeBlob(label)
    removeSEPKey(label)

case "has":
    exit(hasBlob(label) ? 0 : 1)

default:
    usage()
}
