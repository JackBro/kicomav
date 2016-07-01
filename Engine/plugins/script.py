# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # 파일 삭제를 위해 import
import hashlib # MD5 해시를 위해 import
import mmap
import re
import kernel

__revision__ = '$LastChangedRevision: 1 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'

#---------------------------------------------------------------------
# KavMain 클래스
# 키콤백신 엔진 모듈임을 나타내는 클래스이다.
# 이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않는다.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self, plugins)
    # 백신 엔진 모듈의 초기화 작업을 수행한다.
    #-----------------------------------------------------------------
    def init(self, plugins) : # 백신 모듈 초기화
        # script, iframe 정규식
        s_pat = r'<script.*?>([\d\D]*?)</script>'
        i_pat = r'<iframe.*?>([\d\D]*?)</iframe>'
    
        self.s_mat1 = re.compile(s_pat, re.I)
        self.i_mat1 = re.compile(i_pat, re.I)
        
        s_pat = r'\s*<script'
        i_pat = r'\s*<iframe'
        
        self.s_mat2 = re.compile(s_pat, re.I)
        self.i_mat2 = re.compile(i_pat, re.I)

        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # 백신 엔진 모듈의 종료화 작업을 수행한다.
    #-----------------------------------------------------------------
    def uninit(self) : # 백신 모듈 종료화
        return 0
            
    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = __version__     # 버전
        info['title'] = 'Script/IFrame Engine' # 엔진 설명
        info['kmd_name'] = 'script' # 엔진 파일명

        # 패턴 생성날짜와 시간은 없다면 빌드 시간으로 자동 설정
        info['date']    = 0   # 패턴 생성 날짜 
        info['time']    = 0   # 패턴 생성 시간 
        info['sig_num'] = 0 # 패턴 수
        return info  
        
    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle

            s = self.s_mat2.match(mm[:4096]) # <script로 시작하나?
            if s :
                t = self.s_mat1.findall(mm) 
                size = len(t[0])
                if size != 0 :
                    fformat['size'] = size # 포맷 주요 정보 저장
                
                    ret = {}
                    ret['ff_script'] = fformat

                    return ret
                
            s = self.i_mat2.match(mm[:4096]) # <iframe로 시작하나?
            if s :
                t = self.i_mat1.findall(mm) 
                size = len(t[0])
                if size != 0 :
                    fformat['group'] = t # 포맷 주요 정보 저장
                
                    ret = {}
                    ret['ff_iframe'] = fformat

                    return ret
        except :
            pass

        return None
    
    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        try :
            # 미리 분석된 파일 포맷중에 ff_script 포맷이 있는가?
            if format.has_key('ff_script') :                    
                file_scan_list.append(['arc_script', 'JavaScript']) 
            elif format.has_key('ff_iframe') :  
                file_scan_list.append(['arc_iframe', 'IFrame']) # HTML에서 넘어오는거라 IFrame 이름 없어도 됨
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id == 'arc_script' or arc_engine_id == 'arc_iframe' :
                fp = open(arc_name, 'rb')
                buf = fp.read()
                fp.close()      
                
                t = self.s_mat1.findall(buf) 
                if t : 
                    #print '---'
                    #print t[0]
                    return t[0]
                    
                t = self.i_mat1.findall(buf) 
                if t : 
                    #print '---'
                    #print t[0]
                    return t[0]
        except :
            pass

        return None

