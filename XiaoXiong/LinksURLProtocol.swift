import Foundation

/// apptrace 的链接供应器（移植自 3105 的 `LinksURLProtocol`）。
///
/// `apptrace` 二进制里硬编码了请求地址 `http://127.0.0.1:8888`（strings 可见），
/// 期望从本机拿到 links 配置。这里在进程内注册一个 `NSURLProtocol`，在
/// `NSURLConnection` 层直接拦下该 host:port 的请求，返回 bundle 里 `links.txt`
/// 的**原始密文**（`base64(AES-128-CBC(JSON 数组))`），与 3105 里回环服务器
/// 返回的 body 完全一致。
///
/// 这样不建 socket、不 bind/listen/accept、不走回环网络，避免端口占用、沙盒
/// 网络策略、bind 失败之类的问题。apptrace 用的是
/// `sendSynchronousRequest:returningResponse:error:`，一定会经过全局已注册的
/// `NSURLProtocol`，不会被绕过。
///
/// 调用时机：必须在 `dlopen` apptrace **之前** 调用 `registerIfNeeded()`
/// （`LegacyTracePipeline.startIfNeeded()` 内部已经保证）。
final class LinksURLProtocol: URLProtocol {
    private static let host = "127.0.0.1"
    private static let port = 8888

    private static let lock = NSLock()
    private static var registered = false

    /// 幂等注册，进程内只生效一次
    static func registerIfNeeded() {
        lock.lock()
        let isFirstCall = !registered
        registered = true
        lock.unlock()
        guard isFirstCall else { return }
        URLProtocol.registerClass(LinksURLProtocol.self)
        NSLog("apptrace: LinksURLProtocol registered — intercepting http://\(host):\(port)")
    }

    /// links.txt 的原始内容；延迟到第一次真正被请求时才读 bundle
    static let body: Data? = {
        guard let url = Bundle.main.url(forResource: "links", withExtension: "txt"),
              let data = try? Data(contentsOf: url),
              !data.isEmpty else {
            NSLog("apptrace: links.txt missing or empty in bundle root")
            return nil
        }
        NSLog("apptrace: links.txt loaded (\(data.count) bytes)")
        return data
    }()

    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url,
              url.scheme?.lowercased() == "http",
              url.host == host,
              url.port == port else { return false }
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let client = client else { return }
        guard let body = Self.body,
              let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Type": "text/plain",
                    "Content-Length": "\(body.count)",
                ]
              ) else {
            let error = NSError(
                domain: NSURLErrorDomain,
                code: NSURLErrorCannotConnectToHost,
                userInfo: [NSLocalizedDescriptionKey: "links.txt unavailable"]
            )
            client.urlProtocol(self, didFailWithError: error)
            return
        }
        NSLog("apptrace: serving \(body.count) bytes for \(url.absoluteString)")
        client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: body)
        client.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
        // 同步一次性返回，没有需要取消的后台任务
    }
}
