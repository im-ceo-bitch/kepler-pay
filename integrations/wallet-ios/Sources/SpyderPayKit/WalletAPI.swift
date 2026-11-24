import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum WalletError: Error, Equatable { case invalidInput, invalidResponse, http(Int), mismatch, unsupportedCard }
public struct Account: Decodable, Sendable { public let id, kind, currency, status: String; public let balance: Int64 }
public struct InvoicePreview: Decodable, Sendable {
    public let id, merchant_account, expires_at, currency: String
    public let amount: Int64
    public let sandbox, requires_payment_approval: Bool
    public func validate() throws {
        guard UUID(uuidString:id) != nil, UUID(uuidString:merchant_account) != nil, amount > 0, amount <= 100_000_000, currency == "UZS", sandbox, requires_payment_approval else { throw WalletError.invalidResponse }
        let parser = ISO8601DateFormatter(); parser.formatOptions = [.withInternetDateTime,.withFractionalSeconds]
        let expiry = parser.date(from:expires_at) ?? ISO8601DateFormatter().date(from:expires_at)
        guard let expiry, expiry > Date() else { throw WalletError.invalidResponse }
    }
}
public struct Approval: Decodable, Sendable {
    public let approval_id, expires_at, state: String
    public let real_money: Bool
    public let operation: String?
    public let details: Details?
    public struct Details: Decodable, Sendable { public let invoice_id, merchant_account, currency: String; public let amount: Int64 }
}
public struct Receipt: Decodable, Sendable {
    public let id, state, merchant_account, payer_account, payment_journal: String
    public let amount: Int64
    public let refunded_total: Int64?
    public let currency: String?
    public let real_money: Bool?
}
public struct CardChallenge: Decodable, Sendable {
    public let challenge_id, card_id, message_hex, expires_at, algorithm: String
    public let sandbox, payment_authority: Bool
    public func message() throws -> Data {
        guard UUID(uuidString:challenge_id) != nil, UUID(uuidString:card_id) != nil, sandbox, !payment_authority, algorithm == "ECDSA-P256-SHA256-DER", message_hex.count <= 4096, let data = Data(strictHex:message_hex) else { throw WalletError.invalidResponse }
        let parser = ISO8601DateFormatter(); parser.formatOptions = [.withInternetDateTime,.withFractionalSeconds]
        guard let expiry = parser.date(from:expires_at) ?? ISO8601DateFormatter().date(from:expires_at), expiry > Date(), expiry.timeIntervalSinceNow <= 120 else { throw WalletError.invalidResponse }
        guard let fields = try JSONSerialization.jsonObject(with:data) as? [Any], fields.count == 14, fields[0] as? String == "spyderpay-card-proof-v1-prelicense", fields[1] as? String == challenge_id, fields[6] as? String == card_id else { throw WalletError.invalidResponse }
        return data
    }
}
public struct CardProof: Decodable, Sendable {
    public let card_id, state: String
    public let hardware_attested, requires_payment_approval: Bool?
}
public extension Data {
    init?(strictHex: String) {
        let bytes = Array(strictHex.utf8); guard bytes.count % 2 == 0 else { return nil }
        func digit(_ x: UInt8) -> UInt8? { if (48...57).contains(x) {return x-48}; if (97...102).contains(x) {return x-87}; return nil }
        var out = Data(); for i in stride(from:0,to:bytes.count,by:2) { guard let a = digit(bytes[i]), let b = digit(bytes[i+1]) else {return nil}; out.append(a*16+b) }; self=out
    }
    var lowerHex: String { map { String(format:"%02x",$0) }.joined() }
}
/// Never follows redirects or stores a bearer token in persistent URLSession storage.
private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
public struct PaymentIntent: Codable, Sendable {
    public let invoice, merchant, payer, idempotency: String
    public let amount: Int64
    public init(preview: InvoicePreview, payer: String, reference: UUID = UUID()) throws {
        try preview.validate(); guard UUID(uuidString:payer) != nil else { throw WalletError.invalidInput }
        invoice=preview.id; merchant=preview.merchant_account; amount=preview.amount; self.payer=payer; idempotency="wallet-pay-"+reference.uuidString.lowercased()
    }
    public func validate() throws {
        guard [invoice,merchant,payer].allSatisfy({UUID(uuidString:$0) != nil}), amount>0, amount<=100_000_000, idempotency.hasPrefix("wallet-pay-"), UUID(uuidString:String(idempotency.dropFirst(11))) != nil else { throw WalletError.invalidInput }
    }
    public func verify(_ receipt: Receipt) throws {
        guard receipt.id == invoice, receipt.merchant_account == merchant, receipt.payer_account == payer, receipt.amount == amount, UUID(uuidString:receipt.payment_journal) != nil, ["paid","refunded"].contains(receipt.state), receipt.currency == nil || receipt.currency == "UZS", receipt.real_money != true, receipt.refunded_total.map({(0...amount).contains($0)}) ?? true else { throw WalletError.mismatch }
    }
}
public actor WalletAPI {
    public typealias TokenProvider = @Sendable () async throws -> String
    private let origin: URL, session: URLSession, token: TokenProvider
    public init(origin: URL, token: @escaping TokenProvider) throws {
        guard let c = URLComponents(url:origin,resolvingAgainstBaseURL:false), c.scheme == "https", c.host != nil, c.user == nil, c.password == nil, c.query == nil, c.fragment == nil, ["","/"].contains(c.path) else { throw WalletError.invalidInput }
        self.origin=origin; self.token=token
        let config = URLSessionConfiguration.ephemeral; config.urlCache=nil; config.httpCookieStorage=nil; config.urlCredentialStorage=nil; config.timeoutIntervalForRequest=10; config.timeoutIntervalForResource=15
        session=URLSession(configuration:config,delegate:NoRedirect(),delegateQueue:nil)
    }
    private func request<T:Decodable>(_ path: String, method: String="GET", body: [String:Any]?=nil, idem: String?=nil, approval: String?=nil) async throws -> T {
        guard let url=URL(string:path,relativeTo:origin)?.absoluteURL, url.host == origin.host, url.scheme == origin.scheme, url.port == origin.port else {throw WalletError.invalidInput}
        var r=URLRequest(url:url); r.httpMethod=method; r.cachePolicy = .reloadIgnoringLocalCacheData
        let t=try await token(); guard t.utf8.count<=8192, t.range(of:"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",options:.regularExpression) != nil else {throw WalletError.invalidInput}
        r.setValue("Bearer "+t,forHTTPHeaderField:"Authorization"); r.setValue("application/json",forHTTPHeaderField:"Accept")
        if let body {r.httpBody=try JSONSerialization.data(withJSONObject:body); r.setValue("application/json",forHTTPHeaderField:"Content-Type")}
        if let idem {r.setValue(idem,forHTTPHeaderField:"Idempotency-Key")}; if let approval {r.setValue(try id(approval),forHTTPHeaderField:"X-Spyder-Approval")}
        let (data,response)=try await session.data(for:r); guard let http=response as? HTTPURLResponse else {throw WalletError.invalidResponse}; guard http.statusCode==200 else {throw WalletError.http(http.statusCode)}; guard data.count<=131072 else {throw WalletError.invalidResponse}
        return try JSONDecoder().decode(T.self,from:data)
    }
    private func id(_ s:String) throws -> String {guard UUID(uuidString:s) != nil else {throw WalletError.invalidInput};return s.lowercased()}
    public func accounts() async throws -> [Account] { struct Result:Decodable{let accounts:[Account]}; let r:Result=try await request("/v3/accounts"); return r.accounts.filter{$0.kind=="customer" && $0.currency=="UZS" && $0.status=="active" && $0.balance>=0 && UUID(uuidString:$0.id) != nil} }
    public func preview(qr:String) async throws -> InvoicePreview {guard qr.count<=2048, qr.range(of:"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",options:.regularExpression) != nil else {throw WalletError.invalidInput};let p:InvoicePreview=try await request("/v3/pos/preview",method:"POST",body:["token":qr]);try p.validate();return p}
    /// Persist PaymentIntent before sending. Present amount/merchant for consent. Then invoke external IdP MFA.
    public func challenge(_ intent:PaymentIntent) async throws -> Approval {try intent.validate();let a:Approval=try await request("/v3/approvals",method:"POST",body:["operation":"pay_invoice","invoice_id":intent.invoice,"payer":intent.payer,"expected_amount":intent.amount,"expected_merchant":intent.merchant],idem:intent.idempotency);guard a.state=="mfa_required", !a.real_money, a.operation=="pay_invoice", a.details?.invoice_id==intent.invoice, a.details?.merchant_account==intent.merchant, a.details?.amount==intent.amount, a.details?.currency=="UZS", UUID(uuidString:a.approval_id) != nil else {throw WalletError.mismatch};return a}
    /// The token provider MUST now supply the fresh step-up token in the same IdP session.
    public func confirm(_ challenge:Approval) async throws -> Approval {guard challenge.state=="mfa_required", !challenge.real_money else {throw WalletError.invalidInput};let a:Approval=try await request("/v3/approvals/"+id(challenge.approval_id)+"/confirm",method:"POST",body:[:]);guard a.approval_id==challenge.approval_id,a.state=="confirmed",!a.real_money else {throw WalletError.mismatch};return a}
    public func pay(_ intent:PaymentIntent,confirmed:Approval) async throws -> Receipt {try intent.validate();guard confirmed.state=="confirmed",!confirmed.real_money else {throw WalletError.invalidInput};let r:Receipt=try await request("/v3/invoices/"+id(intent.invoice)+"/pay",method:"POST",body:["payer_account":intent.payer],idem:intent.idempotency,approval:confirmed.approval_id);try intent.verify(r);return r}
    /// After an uncertain POST, do NOT create another sale or intent. Query the original receipt first.
    public func recover(_ intent:PaymentIntent) async throws -> Receipt {try intent.validate();let r:Receipt=try await request("/v3/invoices/"+id(intent.invoice)+"/receipt");guard r.real_money==false,r.currency=="UZS" else {throw WalletError.invalidResponse};try intent.verify(r);return r}
    public func enroll(publicKey:Data) async throws -> CardChallenge {guard publicKey.count==65, publicKey.first==4 else {throw WalletError.invalidInput};let r:CardChallenge=try await request("/v3/cards/enroll",method:"POST",body:["public_key":publicKey.lowerHex]);_ = try r.message();return r}
    public func cardPreview(card:String,invoice:String) async throws -> CardChallenge {let r:CardChallenge=try await request("/v3/cards/"+id(card)+"/preview",method:"POST",body:["invoice_id":try id(invoice)]);guard r.card_id==card.lowercased() else {throw WalletError.mismatch};_ = try r.message();return r}
    public func proof(_ challenge:CardChallenge,signature:Data) async throws -> CardProof { _ = try challenge.message();guard (8...72).contains(signature.count),signature.first==0x30 else {throw WalletError.invalidInput};let r:CardProof=try await request("/v3/cards/challenges/"+id(challenge.challenge_id)+"/proof",method:"POST",body:["signature":signature.lowerHex]);guard r.card_id==challenge.card_id, ["enrolled","possession_verified"].contains(r.state),r.hardware_attested != true, r.state != "possession_verified" || r.requires_payment_approval==true else {throw WalletError.invalidResponse};return r }
}
