# -*- coding:utf-8 -*-

"""
Copyright (C) 2013-2014 Nurilab.

Author: Kei Choi(hanul93@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

__revision__ = '$LastChangedRevision: 2 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import kernel
import re

HTML_KEY_COUNT = 3

#---------------------------------------------------------------------
# KavMain Ŭ����
# Ű�޹�� ���� ������� ��Ÿ���� Ŭ�����̴�.
# �� Ŭ������ ������ ��� ���� Ŀ�� ��⿡�� �ε����� �ʴ´�.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self, plugins)
    # ��� ���� ����� �ʱ�ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def init(self, plugins) : # ��� ��� �ʱ�ȭ
        # HTML Ű����
        pat = r'<html\b|\bDOCTYPE\b|<head\b|<title\b|<meta\b|\bhref\b|\blink\b|<body\b'
        self.html_p = re.compile(pat, re.I)
        
        # script, iframe Ű����
        pat = '<script.*?>[\d\D]*?</script>|<iframe.*?>[\d\D]*?</iframe>'
        self.scr_p = re.compile(pat, re.I)
        

        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # ��� ���� ����� ����ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def uninit(self) : # ��� ��� ����ȭ
        return 0
    
    #-----------------------------------------------------------------
    # getinfo(self)
    # ��� ���� ����� �ֿ� ������ �˷��ش�. (����, ������...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # ������ ���� ����
        info['author'] = 'Kei Choi' # ������
        info['version'] = __version__ # ����
        info['title'] = 'HTML Engine' # ���� ����
        info['kmd_name'] = 'html' # ���� ���ϸ�
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # ���� ������ ���� ����

            mm = mmhandle

            s = self.html_p.findall(mm[:4096])
            s = list(set(s))
            
            # print '[*] THTML KEYWORD :', len(s)
            
            if len(s) >= HTML_KEY_COUNT : 
                fformat['keyword'] = s # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_html'] = fformat
                                
                return ret
        except :
            pass

        return None
        
    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # �˻� ��� ������ ��� ����

        try :
            # �̸� �м��� ���� �����߿� ff_text ������ �ִ°�?
            fformat = format['ff_html']
            
            fp = open(filename, 'rb')
            buf = fp.read()
            fp.close()
            
            s = self.html_p.findall(buf)
            s = list(set(s))
                        
            if len(s) >= HTML_KEY_COUNT : # HTML Ű���尡 3�� �̻� �߰ߵǸ� HTML ����
                # script�� iframe ����Ʈ�� �����.
                
                s_count = 1
                i_count = 1
                                
                for obj in self.scr_p.finditer(buf) :
                    t1 = obj.group()
                    # t2 = obj.span()
                    
                    if t1.lower().find('<script') != -1 : 
                        file_scan_list.append(['arc_html', 'HTML/Script #%d' % s_count])
                        s_count += 1
                    else :    
                        file_scan_list.append(['arc_html', 'HTML/IFrame #%d' % i_count])
                        i_count += 1
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_html' :
                raise SystemError

            fp = open(arc_name, 'rb')
            buf = fp.read()
            fp.close()
            
            s = self.html_p.findall(buf)
            s = list(set(s))
            if len(s) >= HTML_KEY_COUNT : # HTML Ű���尡 3�� �̻� �߰ߵǸ� HTML ����
                # script�� iframe ����Ʈ�� ã�´�.
                
                s_count = 1
                i_count = 1
                
                for obj in self.scr_p.finditer(buf) :
                    t1 = obj.group()
                    t2 = obj.span()
                    
                    k = ''
                    if t1.lower().find('<script') != -1 : 
                        k = 'HTML/Script #%d' % s_count
                        s_count += 1
                    else :    
                        k = 'HTML/IFrame #%d' % i_count
                        i_count += 1
                        
                    if k == arc_in_name :
                        data = buf[t2[0]:t2[1]]
                        return data
        except :
            pass

        return None