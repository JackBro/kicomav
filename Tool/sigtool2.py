# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import re
import sys
import os
import marshal

re_comment = r'#[\d\D]*'

size_sig = {} # ũ��� ID ����
p1_sig = [] # ���� MD5 ���� 6Byte
p2_sig = [] # ���� MD5 ���� 10Byte
name_sig = {} # ���̷��� �̸�

def GenVnameKey(vname) :
    v = name_sig.values() # �Ǽ��ڵ� �̸��� ���� ��´�.
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
    
    # ó�� �Էµ� ũ�� �����̸�...
    if size_sig.has_key(size) == False :
        size_sig[size] = id
        
    # ���̷��� �̸��� Key�� �����Ѵ�.
    key = GenVnameKey(name)
    
    p1 = fmd5[:6] # ���� 6Byte
    p2 = fmd5[6:] # ���� 10Byte
    
    # ���� �߰�
    p1_sig.append(p1)
    p2_sig.append((p2, key))
    
def SaveSig(fname, id) :
    # ũ�� ���� ���� : ex) script.s01
    sname = '%s.s%02d' % (fname, id)
    t = marshal.dumps(size_sig)
    SaveFile(sname, t)
    
    # ���� p1 ���� ���� : ex) script.i01
    sname = '%s.i%02d' % (fname, id)
    t = marshal.dumps(p1_sig)
    SaveFile(sname, t)

    # ���� p2 ���� ���� : ex) script.c01
    sname = '%s.c%02d' % (fname, id)
    t = marshal.dumps(p2_sig)
    SaveFile(sname, t)
    
    # ���̷����� ���� ���� : ex) script.n01
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
        
        # �ּ��� �� ȭ��Ʈ �����̽� ����
        line = re.sub(re_comment, '', line)
        line = re.sub(r'\s', '', line)
        
        if len(line) == 0 : continue # �ƹ��͵� ���ٸ� �����ٷ�...
        
        # print line
        AddSig(line, id)
        
    # print p2_sig
    fp.close()
    
    # �־��� ���� ���ϸ��� �̿��ؼ� sig ������ ����
    t = os.path.abspath(fname)
    dir, t = os.path.split(t)
    name = os.path.splitext(t)[0]
    SaveSig(name, id)


if __name__ == '__main__' :
    if len(sys.argv) != 3:
        print 'Usage : sigtool2.py [sig text] [id]'
        exit(0)
        
    ConvertSig(sys.argv[1], int(sys.argv[2]))
    