import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
os.environ['SHARKAI_STORAGE']=tempfile.mkdtemp(prefix='sharkai-test-')
from fastapi.testclient import TestClient
import app as shark
from scapy.all import Ether, IP, TCP, Raw, wrpcap
client=TestClient(shark.app)

def make_pcap(path):
    packets=[Ether()/IP(src='192.0.2.10',dst='198.51.100.20')/TCP(sport=12345,dport=80)/Raw(load=b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\nCTF{test_flag_123}'), Ether()/IP(src='192.0.2.10',dst='198.51.100.20')/TCP(sport=12345,dport=80)/Raw(load=b'hello')]
    wrpcap(str(path),packets)

def test_health(): assert client.get('/api/health').json()['ok'] is True

def test_upload_flags_filters_and_reports(tmp_path):
    path=tmp_path/'tiny.pcap'; make_pcap(path)
    with path.open('rb') as f: r=client.post('/api/captures',files={'file':('tiny.pcap',f,'application/octet-stream')})
    assert r.status_code==200, r.text
    cid=r.json()['id']; d=client.get('/api/captures/'+cid).json()
    assert d['packet_count']==2 and any(x['flag']=='CTF{test_flag_123}' for x in d['flags'])
    assert client.get(f'/api/captures/{cid}/packets?protocol=TCP').json()['total']==2
    assert client.get(f'/api/captures/{cid}/report?format=md').status_code==200
    assert client.get(f'/api/captures/{cid}/report?format=pdf').headers['content-type']=='application/pdf'

def test_reject_extension():
    r=client.post('/api/captures',files={'file':('bad.exe',b'not a pcap','application/octet-stream')})
    assert r.status_code==400

def test_deterministic_ask():
    path=Path(shark.STORAGE)/'manual-test'; path.mkdir(exist_ok=True)
    c={'id':'x','filename':'sample.pcap','sha256':'abc','packet_count':1,'protocols':{'TCP':1},'top_endpoints':[],'top_conversations':[],'dns':[],'http':[],'flags':[],'iocs':[],'files':[],'timeline':[],'packets':[],'tcp_streams':[]}
    shark.captures['test-capture']=c
    r=client.post('/api/captures/test-capture/ask',json={'question':'Any flags?'})
    assert r.status_code==200 and r.json()['mode']=='deterministic'
