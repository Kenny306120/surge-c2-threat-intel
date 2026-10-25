#!/usr/bin/env python3
"""Build Surge IOC rule sets from Feodo and ThreatFox. Requires THREATFOX_AUTH_KEY."""
import os, json, ipaddress, urllib.request, pathlib, datetime
OUT=pathlib.Path('rules'); OUT.mkdir(exist_ok=True)
KEY=os.environ['THREATFOX_AUTH_KEY']
def fetch(url, headers=None, data=None):
    req=urllib.request.Request(url,headers=headers or {'User-Agent':'Surge-IOC-Builder/1.0'},data=data)
    with urllib.request.urlopen(req,timeout=45) as r: return r.read().decode('utf-8-sig')
def ip_rule(s):
    try:
        ip=ipaddress.ip_address(s)
        if not ip.is_global: return None
        return ('IP-CIDR6' if ip.version==6 else 'IP-CIDR')+','+str(ip)+'/'+('128' if ip.version==6 else '32')+',no-resolve'
    except ValueError: return None
def domain_rule(s):
    s=s.strip().lower().rstrip('.')
    if len(s)>253 or not s or '/' in s or ':' in s or '*' in s: return None
    labels=s.split('.')
    if len(labels)<2 or any(not x or len(x)>63 or x[0]=='-' or x[-1]=='-' or not all(c.isascii() and (c.isalnum() or c=='-') for c in x) for x in labels):return None
    return 'DOMAIN,'+s
def save(name, rules):
    p=OUT/name
    rules=sorted(set(rules))
    if not rules: raise RuntimeError('Refusing to publish empty list: '+name)
    p.write_text('# Generated UTC '+datetime.datetime.now(datetime.timezone.utc).isoformat()+'\n'+'\n'.join(rules)+'\n')
    print(name,len(rules))
feodo=fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.txt')
feodo_rules=[r for line in feodo.splitlines() if line.strip() and not line.startswith('#') if (r:=ip_rule(line.strip()))]
save('feodo-surge.list',feodo_rules)
body=json.dumps({'query':'get_iocs','days':7}).encode()
resp=json.loads(fetch('https://threatfox-api.abuse.ch/api/v1/',{'Auth-Key':KEY,'Content-Type':'application/json','User-Agent':'Surge-IOC-Builder/1.0'},body))
if resp.get('query_status')!='ok':raise RuntimeError('ThreatFox API status: '+str(resp.get('query_status')))
rules=[]
for rec in resp.get('data') or []:
    if rec.get('threat_type')!='botnet_cc' or int(rec.get('confidence_level') or 0)<90:continue
    kind=rec.get('ioc_type'); val=str(rec.get('ioc') or '').strip()
    if kind=='domain': r=domain_rule(val)
    elif kind=='ip:port': r=ip_rule(val.rsplit(':',1)[0]) if val.count(':')==1 else None
    else: r=None
    if r:rules.append(r)
save('threatfox-surge.list',rules)
