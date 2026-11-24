/** Private pre-license merchant client. Requires a real IdP access-token provider.
 * No storage, no service/HMAC secrets, no bank/card payment authorization.
 */
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDEM=/^[A-Za-z0-9._:-]{12,128}$/;
export class MerchantClient {
  constructor(origin, getAccessToken, fetcher=globalThis.fetch) {
    const url=new URL(origin);
    if(url.protocol!=="https:" || url.username || url.password || url.pathname!=="/" || url.search || url.hash || typeof getAccessToken!=="function") throw new Error("invalid_merchant_origin");
    this.origin=url.origin; this.getAccessToken=getAccessToken; this.fetcher=fetcher;
  }
  async #request(path, method, body, idem) {
    const token=await this.getAccessToken();
    if(typeof token!=="string" || token.length>8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error("invalid_access_token");
    const headers={Authorization:`Bearer ${token}`,Accept:"application/json"};
    if(body!==undefined)headers["Content-Type"]="application/json";
    if(idem!==undefined){if(!IDEM.test(idem))throw new Error("invalid_idempotency_key");headers["Idempotency-Key"]=idem;}
    // Never auto-retry POST or follow redirects. Caller reuses the same explicit idempotency key.
    const result=await this.fetcher(this.origin+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),redirect:"error",credentials:"omit",cache:"no-store",signal:AbortSignal.timeout(10000)});
    if(!result.ok)throw new Error(`spyderpay_http_${result.status}`);
    return result.json();
  }
  accounts(){return this.#request("/v3/accounts","GET");}
  createInvoice(account,amount,idem,ttl=15){
    if(!UUID.test(account)||!Number.isSafeInteger(amount)||amount<1||amount>100000000||!Number.isInteger(ttl)||ttl<1||ttl>60||typeof idem!=="string"||!IDEM.test(idem))throw new Error("invalid_invoice");
    return this.#request("/v3/invoices","POST",{merchant_account:account,amount,ttl_minutes:ttl},idem);
  }
  invoice(id){if(!UUID.test(id))throw new Error("invalid_invoice_id");return this.#request(`/v3/invoices/${id}`,"GET");}
  signedQrPayload(id){if(!UUID.test(id))throw new Error("invalid_invoice_id");return this.#request(`/v3/pos/invoices/${id}/token`,"POST",{});}
}
