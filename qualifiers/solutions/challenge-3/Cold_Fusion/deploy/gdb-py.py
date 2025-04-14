import gdb
import string
import re

gdb.execute("set pagination off")
gdb.execute("set disable-randomization off")
answer = ""

class RecordAlphabetBreakpoint(gdb.Breakpoint):
    def __init__(self, letter):
        self.letter = letter
        # "func_" 다음에 해당 letter가 10번 반복된 패턴을 사용하여 
        # 예: letter가 "P"이면 "func_PPPPPPPPPP"가 되어 func_P*와 매칭되도록 함
        spec = "func_" + letter * 10
        super(RecordAlphabetBreakpoint, self).__init__(spec, internal=False)
    
    def stop(self):
        global answer
        # 현재 호출된 함수의 이름을 가져옵니다.
        frame = gdb.selected_frame()
        func_name = frame.name() if frame else ""
        # "func_" 뒤에 오는 첫 번째 대문자 알파벳 추출 (예: func_PPPPPPPPPP -> "P")
        m = re.match(r'func_([a-zA-Z])', func_name)
        if m:
            letter = m.group(1)
        else:
            letter = self.letter  # 매칭되지 않으면 기본 letter 사용
        
        try:
            answer += letter
        except Exception as e:
            gdb.write("파일 쓰기 실패: {}\n".format(e))
        # 함수 호출 시 중단하지 않고 계속 실행
        return False

# 모든 알파벳(A~Z)에 대해, 해당 패턴과 일치하는 함수가 실제로 존재할 때만 breakpoint를 생성합니다.
for letter in string.ascii_letters + string.digits:
    # 검색 패턴 예: "func_A"
    pattern = "func_" + letter
    functions_info = gdb.execute("info functions " + pattern, to_string=True)
    # "No functions found"라는 문구가 포함되어 있으면, 해당 알파벳의 함수가 없음 -> 스킵
    if "No functions found" in functions_info:
        continue
    RecordAlphabetBreakpoint(letter)

gdb.execute("r")

# assert answer[:4] == "PASS"

# 결과를 파일로 저장
try:
    with open("/tmp/result.txt", "w") as f:
        # f.write(answer)
        f.write(answer[:4] + '{' + answer[4:] + '}')
except Exception as e:
    gdb.write("파일 쓰기 실패: {}\n".format(e))
    with open("/tmp/result.txt", "w") as f:
        f.write("FAIL")

gdb.execute("quit")