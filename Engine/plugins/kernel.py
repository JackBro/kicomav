# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@naver.com)

import os
import re

# 악성코드 상태값
NOT_FOUND = 0 # 악성코드 찾지 못함
INFECTED  = 1 # 감염
SUSPECT   = 2 # 의심
WARNING   = 3 # 경고


#엔진의 타입
ARCHIVE_ENGINE = 80  # 압축 해제 엔진

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
        # 텍스트 검사를 위해 미리 컴파일
        pat = r'[\w\s!"#$%&\'()*+,\-./:;<=>?@\[\\\]\^_`{\|}~]'
        self.re_text = re.compile(pat)
        
        return 0

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다. 
    # 분석 대상 : 텍스트 파일, 바이너리 파일
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            ret = {}
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle
            size = os.path.getsize(filename)
            
            # 바이너리 정보 추가
            fformat['size'] = size # 포맷 주요 정보 저장
            ret['ff_bin'] = fformat

            # 텍스트인지 확인
            data = mm[:4096] # 4K정도만 읽음
            char_len = len(self.re_text.findall(data)) # 몇개의 텍스트 문자가 있나?
            char_per = (char_len/float(len(data))) * 100
            
            if char_per > 80.0 : # 80% 이상이면
                fformat = {} # 포맷 정보를 담을 공간
                fformat['persent'] = char_per
                ret['ff_text'] = fformat
            
            return ret
        except :
            pass

        return None
        