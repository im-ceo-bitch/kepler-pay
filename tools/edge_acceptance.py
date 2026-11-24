"""Local integration test of the v10 NGINX edge, using only temporary test PKI.
Requires nginx and openssl installed. No real API, bank, credentials or funds.
Runs bounded loopback requests and validates route and credential separation.
"""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]


def run(argv,root):
    subprocess.run(argv,cwd=root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=20)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        data=json.dumps({'path':self.path,'service':self.headers.get('X-Spyder-Key-Id'),'bearer':self.headers.get('Authorization'),'approval':self.headers.get('X-Spyder-Approval')}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*_):pass


def fetch(port,path,context,headers=None):
    c=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=4)
    try:
        c.request('GET',path,headers=headers or {});r=c.getresponse();body=r.read(8192)
        return r.status,json.loads(body) if r.status==200 else None
    finally:c.close()


def check():
    nginx=shutil.which('nginx');openssl=shutil.which('openssl')
    if not nginx or not openssl:raise RuntimeError('nginx_and_openssl_required')
    with tempfile.TemporaryDirectory(prefix='sp-edge-test-') as directory:
        d=Path(directory)
        run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1','-keyout','server.key','-out','server.crt'],d)
        run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=SP-Test-CA','-addext','basicConstraints=critical,CA:TRUE','-keyout','ca.key','-out','ca.crt'],d)
        run([openssl,'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=SP-Test-Service','-keyout','client.key','-out','client.csr'],d)
        (d/'client.ext').write_text('extendedKeyUsage=clientAuth\n')
        run([openssl,'x509','-req','-in','client.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','client.ext','-out','client.crt'],d)
        backend=ThreadingHTTPServer(('127.0.0.1',0),Backend);thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
        client_port,service_port=port(),port()
        if client_port==service_port:raise RuntimeError('port_collision')
        config=(ROOT/'infrastructure/edge/nginx-isolated-v10.conf').read_text()
        for source,dest in {'/run/secrets/staging-cert.crt':str(d/'server.crt'),'/run/secrets/staging-key.key':str(d/'server.key'),'/run/secrets/service-client-ca.crt':str(d/'ca.crt'),'127.0.0.1:8443':f'127.0.0.1:{client_port}','127.0.0.1:8444':f'127.0.0.1:{service_port}','127.0.0.1:8766':f'127.0.0.1:{backend.server_port}'}.items():config=config.replace(source,dest)
        (d/'nginx.conf').write_text('daemon off; master_process off;\npid '+str(d/'nginx.pid')+';\nerror_log '+str(d/'error.log')+';\nevents { worker_connections 64; }\nhttp { client_body_temp_path '+str(d/'body')+'; proxy_temp_path '+str(d/'proxy')+'; fastcgi_temp_path '+str(d/'fastcgi')+'; uwsgi_temp_path '+str(d/'uwsgi')+'; scgi_temp_path '+str(d/'scgi')+';\n'+config+'\n}')
        argv=[nginx,'-p',str(d)+'/', '-c',str(d/'nginx.conf')]
        proc=None
        try:
            run(argv+['-t'],d)
            proc=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            plain=ssl.create_default_context(cafile=d/'server.crt');mtls=ssl.create_default_context(cafile=d/'server.crt');mtls.load_cert_chain(d/'client.crt',d/'client.key')
            for _ in range(40):
                try:fetch(client_port,'/v3/accounts',plain);break
                except OSError:time.sleep(.1)
            else:raise RuntimeError('edge_not_started')
            tests=[]
            def require(name,condition):
                if not condition:raise RuntimeError('edge_check_failed:'+name)
                tests.append(name)
            status,body=fetch(client_port,'/v3/accounts',plain,{'X-Spyder-Key-Id':'fixture','Authorization':'Bearer fixture'})
            require('client_service_header_stripped',status==200 and body['service'] is None and body['bearer']=='Bearer fixture')
            for route in ('/v3/ops/ready','/v3/bank/intents','/v3/rail/intents/a','/v3/finance/fees','/health/ready'):
                require('client_denied:'+route,fetch(client_port,route,plain)[0]==404)
            try:status,_=fetch(service_port,'/v3/ops/ready',plain);denied=status>=400
            except ssl.SSLError:denied=True
            require('service_requires_client_certificate',denied)
            status,body=fetch(service_port,'/v3/ops/ready',mtls,{'Authorization':'Bearer fixture','X-Spyder-Approval':'fixture','X-Spyder-Key-Id':'fixture'})
            require('service_user_headers_stripped',status==200 and body['service']=='fixture' and body['bearer'] is None and body['approval'] is None)
            for route in ('/v3/accounts','/v3/ops/sandbox/credits','/health/ready'):
                require('service_denied:'+route,fetch(service_port,route,mtls)[0]==404)
            return {'scope':'loopback_test_pki_mock_backend','passed':len(tests),'checks':tests,'real_money':False}
        finally:
            if proc:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            backend.shutdown();backend.server_close()

if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args();print(json.dumps(check(),sort_keys=True))
