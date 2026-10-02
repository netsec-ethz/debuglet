# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Generate original, synthetic MMDB fixtures; no external geographic data."""
from pathlib import Path

def enc(value):
    if isinstance(value, str):
        b=value.encode(); typ=2; size=len(b)
    elif isinstance(value, dict):
        b=b''.join(enc(k)+enc(v) for k,v in value.items()); typ=7; size=len(value)
    elif isinstance(value, list):
        b=b''.join(enc(v) for v in value);typ=11;size=len(value)
    else:
        b=int(value).to_bytes(max(1,(int(value).bit_length()+7)//8),'big');typ=6;size=len(b)
    assert size<285
    extra=b'' if size<29 else bytes([size-29])
    size=min(size,29)
    return (bytes([(typ<<5)|size]) if typ<8 else bytes([size,typ-7]))+extra+b

def write(name, record, dbtype, other=None):
    metadata={'binary_format_major_version':2,'binary_format_minor_version':0,'build_epoch':1700000000,'database_type':dbtype,'description':{'en':'Synthetic test only'},'ip_version':4,'languages':['en'],'node_count':1,'record_size':24}
    # Both root children point to a single synthetic record. No claims about
    # real networks: test code only looks up fixture keys and sends no packets.
    first=enc(record)
    right=17 if other is None else 17+len(first)
    data=(17).to_bytes(3,'big')+right.to_bytes(3,'big')+b'\0'*16+first+(b'' if other is None else enc(other))+b'\xab\xcd\xefMaxMind.com'+enc(metadata)
    Path(__file__).with_name(name).write_bytes(data)

write('asn.mmdb',{'autonomous_system_number':64500,'autonomous_system_organization':'Synthetic network'},'Debuglet-Test-ASN')
write('city.mmdb',{'country':{'iso_code':'CH'},'city':{'names':{'en':'Fixture city'}}},'Debuglet-Test-City')
write('country.mmdb',{'country':{'iso_code':'DE'}},'Debuglet-Test-Country')
write('invalid.mmdb',{'country':{'iso_code':'xx'},'autonomous_system_number':0},'Debuglet-Test-Invalid')

# An empty half of the tree proves a global key may still be unknown.
p=Path(__file__).with_name('asn.mmdb')
Path(__file__).with_name('empty.mmdb').write_bytes((1).to_bytes(3,'big')+(17).to_bytes(3,'big')+p.read_bytes()[6:])

write('different.mmdb',
      {'autonomous_system_number':64500,'autonomous_system_organization':'Synthetic west','country':{'iso_code':'CH'},'city':{'names':{'en':'Fixture city'}}},
      'Debuglet-Test-Different',
      {'autonomous_system_number':64501,'autonomous_system_organization':'Synthetic east','country':{'iso_code':'DE'},'city':{'names':{'en':'Other fixture'}}})
