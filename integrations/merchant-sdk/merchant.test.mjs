import test from 'node:test';
import assert from 'node:assert/strict';
import {MerchantClient} from './merchant.mjs';
const account='00000000-0000-4000-8000-000000000001';
const idem='test-invoice-0001';
const client=fetcher=>new MerchantClient('https://private.example.test',async()=> 'test.token.signature',fetcher);
test('merchant invoice contract',async()=>{
  const c=client(async(url,options)=>{assert.equal(url,'https://private.example.test/v3/invoices');assert.equal(options.headers['Idempotency-Key'],idem);assert.equal(options.headers.Authorization,'Bearer test.token.signature');assert.equal(options.redirect,'error');assert.deepEqual(JSON.parse(options.body),{merchant_account:account,amount:12345,ttl_minutes:15});return {ok:true,json:async()=>({id:account})};});
  assert.equal((await c.createInvoice(account,12345,idem)).id,account);
});
test('invalid input is rejected before network',()=>{const c=client(()=>assert.fail('unexpected request'));for(const amount of [0,-1,1.5,100000001,NaN])assert.throws(()=>c.createInvoice(account,amount,idem));assert.throws(()=>c.createInvoice(account,1,'short'));assert.throws(()=>c.signedQrPayload('../escape'));});
test('reject insecure or credentialed origin',()=>{for(const o of ['http://a.test','https://user:pw@a.test','https://a.test/path'])assert.throws(()=>new MerchantClient(o,()=>''));});
test('no automatic retry',async()=>{let count=0;const c=client(async()=>{count++;return {ok:false,status:503};});await assert.rejects(c.createInvoice(account,123,idem),/503/);assert.equal(count,1);});
