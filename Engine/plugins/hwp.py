# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # ���� ������ ���� import
import zlib
import struct, mmap
import kernel

class HWPTag :
    fnTagID = {0x43:'self.HWPTAG_PARA_TEXT'}

    def HWPTAG_PARA_TEXT(self, buf, lenbuf) :
        ret = 0
        pos = 0
        ctrl_ch = False
        str_txt = ''
        old_ch = 0
        ch_count = 0

        while pos < lenbuf:
            ch = self.GetWord(buf, pos)
            # print ch, pos

            if ch >= 1 and ch <= 9 : # 16����Ʈ �����
                ctrl_ch = True
                pos += 16
            elif ch == 11 or ch == 12 : # 16����Ʈ �����
                ctrl_ch = True
                pos += 16
            elif ch >= 14 and ch <= 23 : # 16����Ʈ �����
                ctrl_ch = True
                pos += 16
            elif ch <= 31 :  # 2����Ʈ �����
                ctrl_ch = True
                pos += 2

            # ���ܿ� ���Ե� ����
            if ctrl_ch == False :
                str_txt += unichr(ch)
                pos += 2
                # �ش� ������ �ݺ����� üũ�غ���
                if old_ch == ch :
                    ch_count += 1
                else :
                    old_ch = ch
                    ch_count = 0
            else :
                ctrl_ch = False

            # ������ �ݺ����� ���ϸ� Exploit ������ ���ɼ��� ũ��
            if ch_count > 4096 :
                ret  = -1
                break

        # print str_txt.encode('utf-8')
        return ret


    def GetInfo(self, val) :
        b = 0b1111111111
        c = 0b111111111111
        Size  = (val >> 20) & c
        TagID = (val &b)
        Level = ((val >> 10) & b)

        return TagID, Level, Size


    def GetDword(self, buf, off) :
        return struct.unpack('<L', buf[off:off+4])[0]


    def GetWord(self, buf, off) :
        return struct.unpack('<H', buf[off:off+2])[0]


    def Check(self, buf, lenbuf, isCompressed) :
        ret = -1
        pos = 0

        if isCompressed == 1 :
            buf = zlib.decompress(buf, -15)
            lenbuf = len(buf)

        while pos < lenbuf :
            extra_size = 4
            val = self.GetDword(buf, pos)
            tagid, level, size = self.GetInfo(val)

            if size == 0xfff :
                extra_size = 8
                size = self.GetDword(buf, pos+4)

            try :
                '''
                print
                print 'tag : %02X' % tagid
                print 'pos : %X (%s)' % (pos, self.fnTagID[tagid])
                '''
                fn = 'ret_tag = %s(buf[pos+extra_size:pos+size+extra_size], size)' % self.fnTagID[tagid]
                exec(fn)

                if ret_tag == -1 :
                    return -1, tagid
            except :
                '''
                #print traceback.format_exc ()
                print 'pos : %X (NONE)' % (pos)
                '''
                pass

            pos += (size + extra_size)

        if pos == lenbuf :
            ret = 0

        return ret, tagid

#---------------------------------------------------------------------
# KavMain Ŭ����
# Ű�޹�� ���� ������� ��Ÿ���� Ŭ�����̴�.
# �� Ŭ������ ������ ��� ���� Ŀ�� ��⿡�� �ε����� �ʴ´�.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self)
    # ��� ���� ����� �ʱ�ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def init(self) : # ��� ��� �ʱ�ȭ
        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # ��� ���� ����� ����ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def uninit(self) : # ��� ��� ����ȭ
        return 0
    
    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # �Ǽ��ڵ带 �˻��Ѵ�.
    # ���ڰ� : mmhandle         - ���� mmap �ڵ�
    #        : scan_file_struct - ���� ����ü
    #        : format           - �̸� �м��� ���� ����
    # ���ϰ� : (�Ǽ��ڵ� �߰� ����, �Ǽ��ڵ� �̸�, �Ǽ��ڵ� ID) ���
    #-----------------------------------------------------------------
    def scan(self, mmhandle, scan_file_struct, format) :
        ret_value = {}
        ret_value['result']     = False # ���̷��� �߰� ����
        ret_value['virus_name'] = ''    # ���̷��� �̸�
        ret_value['scan_state'] = kernel.NOT_FOUND # 0:����, 1:����, 2:�ǽ�, 3:���
        ret_value['virus_id']   = -1    # ���̷��� ID

        try :
            # HWP Exploit�� �ַ� BodyText/SectionXX�� �����Ѵ�
            # ������ ���� �Ǽ��ڵ� ���ϸ�ŭ ���Ͽ��� �д´�.
            section_name = scan_file_struct['deep_filename']

            if section_name.find(r'BodyText/Section') == -1 :
                raise SystemError

            data = mmhandle[:] # ���� ��ü ����

            # HWP�� �߸��� �±׸� üũ�Ѵ�.
            h = HWPTag()
            ret, tagid = h.Check(data, len(data), 1)
            if tagid == 0x5A : # Tagid�� 0x5A�ΰ��� �Ǽ��ڵ� Ȯ��
                scan_state = kernel.INFECTED # ����
            else :
                scan_state = kernel.SUSPECT  # �ǽ�

            if ret != 0 :
                # �Ǽ��ڵ� ������ ���ٸ� ��� ���� �����Ѵ�.
                s = 'Exploit.HWP.Generic.%2X' % tagid
                ret_value['result']     = True # ���̷��� �߰� ����
                ret_value['virus_name'] = s    # ���̷��� �̸�
                ret_value['scan_state'] = scan_state # 0:����, 1:����, 2:�ǽ�, 3:���
                ret_value['virus_id']   = 0    # ���̷��� ID
                return ret_value
        except :
            pass

        # �Ǽ��ڵ带 �߰����� �������� �����Ѵ�.
        return ret_value

    #-----------------------------------------------------------------
    # disinfect(self, filename, malwareID)
    # �Ǽ��ڵ带 ġ���Ѵ�.
    # ���ڰ� : filename   - ���� �̸�
    #        : malwareID  - ġ���� �Ǽ��ڵ� ID
    # ���ϰ� : �Ǽ��ڵ� ġ�� ����
    #-----------------------------------------------------------------
    def disinfect(self, filename, malwareID) : # �Ǽ��ڵ� ġ��
        try :
            '''
            # �Ǽ��ڵ� ���� ������� ���� ID ���� 0�ΰ�?
            if malwareID == 0 : 
                os.remove(filename) # ���� ����
                return True # ġ�� �Ϸ� ����
            '''
        except :
            pass

        return False # ġ�� ���� ����

    #-----------------------------------------------------------------
    # listvirus(self)
    # ����/ġ�� ������ �Ǽ��ڵ��� ����� �˷��ش�.
    #-----------------------------------------------------------------
    def listvirus(self) : # ���� ������ �Ǽ��ڵ� ���
        vlist = [] # ����Ʈ�� ���� ����
        vlist.append('Exploit.HWP.Gen.43') 
        vlist.append('Exploit.HWP.Gen.5A')
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # ��� ���� ����� �ֿ� ������ �˷��ش�. (����, ������...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # ������ ���� ����
        info['author'] = 'Kei Choi' # ������
        info['version'] = '1.0'     # ����
        info['title'] = 'HWP Exploit Engine' # ���� ����
        info['kmd_name'] = 'hwp' # ���� ���ϸ�
        return info
