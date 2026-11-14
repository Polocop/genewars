import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
import struct, pathlib, hashlib
p=pathlib.Path((_GW_ROOT + '\\evidence\\genewars-1_1.exe')); b=p.read_bytes(); le=struct.unpack_from('<I',b,0x3c)[0]; h=le
rd=lambda off,fmt:struct.unpack_from('<'+fmt,b,h+off)[0]
print('file',len(b),'sha256',hashlib.sha256(b).hexdigest(),'leoff',hex(le),'sig',b[h+2:h+4])
for key,off,fmt in [('pages',0x14,'I'),('objtab',0x40,'I'),('nobj',0x44,'I'),('pagetab',0x48,'I'),('fixpage',0x68,'I'),('fixrec',0x6c,'I'),('data_pages',0x80,'I')]:print(key,hex(rd(off,fmt)))
page_size=rd(0x28,'I'); n=rd(0x44,'I'); objtab=rd(0x40,'I'); pagetab=rd(0x48,'I')
for i in range(n):
 pos=h+objtab+i*24
 vals=struct.unpack_from('<IIIIII',b,pos)
 print('object',i+1, 'virtual_size/base/flags/pagemap/pages',*[hex(x) for x in vals])
print('page map entries first 16')
for i in range(16):
 pos=h+pagetab+i*4
 print(i+1,b[pos:pos+4].hex(),struct.unpack_from('<HBB',b,pos))
bytesp=pathlib.Path((_GW_ROOT + '\\evidence\\genewars-1_1.bytes')).read_bytes(); print('byteslen',len(bytesp),'pages',len(bytesp)//page_size,'page size',page_size,'sha',hashlib.sha256(bytesp).hexdigest())
print('extracted pages offset sample',b[h+rd(0x80,'I'):h+rd(0x80,'I')+16].hex())
print('bytes first',bytesp[:16].hex())
