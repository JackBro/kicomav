# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import re
import sys
import os
import marshal

re_comment = r'#[\d\D]*'

size_sig = {} # 크기와 ID 저장
p1_sig = [] # 패턴 MD5 앞쪽 6Byte
p2_sig = [] # 패턴 MD5 앞쪽 10Byte
name_sig = {} # 바이러스 이름

def GenVnameKey(vname) :
    v = name_sig.values() # 악성코드 이름을 전부 얻는다.
    if vname in v :
        idx = v.index(vname)
    else :
        idx = len(v)
        name_sig[idx] = vname
        
    return idx

def AddSig(line, id) :
    t = line.split(':')
    
    size = int(t[0]) # size
    fmd5 = t[1].decode('hex') # md5
    name = t[2]
    
    # 처음 입력된 크기 패턴이면...
    if size_sig.has_key(size) == False :
        size_sig[size] = id
        
    # 바이러스 이름의 Key를 생성한다.
    key = GenVnameKey(name)
    
    p1 = fmd5[:6] # 앞쪽 6Byte
    p2 = fmd5[6:] # 뒤쪽 10Byte
    
    # 패턴 추가
    p1_sig.append(p1)
    p2_sig.append((p2, key))
    
def SaveSig(fname, id) :
    # 크기 파일 저장 : ex) script.s01
    sname = '%s.s%02d' % (fname, id)
    t = marshal.dumps(size_sig)
    SaveFile(sname, t)
    
    # 패턴 p1 파일 저장 : ex) script.i01
    sname = '%s.i%02d' % (fname, id)
    t = marshal.dumps(p1_sig)
    SaveFile(sname, t)

    # 패턴 p2 파일 저장 : ex) script.c01
    sname = '%s.c%02d' % (fname, id)
    t = marshal.dumps(p2_sig)
    SaveFile(sname, t)
    
    # 바이러스명 파일 저장 : ex) script.n01
    sname = '%s.n%02d' % (fname, id)
    t = marshal.dumps(name_sig)
    SaveFile(sname, t)
    
    
def SaveFile(fname, data) :
    fp = open(fname, 'wb')
    fp.write(data)
    fp.close()


def ConvertSig(fname, id) :
    fp = open(fname, 'rb')
    
    while True :
        line = fp.readline()
        if not line : break
        
        # 주석문 및 화이트 스페이스 제거
        line = re.sub(re_comment, '', line)
        line = re.sub(r'\s', '', line)
        
        if len(line) == 0 : continue # 아무것도 없다면 다음줄로...
        
        # print line
        AddSig(line, id)
        
    # print p2_sig
    fp.close()
    
    # 주어진 패턴 파일명을 이용해서 sig 파일을 만듦
    t = os.path.abspath(fname)
    dir, t = os.path.split(t)
    name = os.path.splitext(t)[0]
    SaveSig(name, id)


if __name__ == '__main__' :
    if len(sys.argv) != 3:
        print 'Usage : sigtool2.py [sig text] [id]'
        exit(0)
        
    ConvertSig(sys.argv[1], int(sys.argv[2]))
    