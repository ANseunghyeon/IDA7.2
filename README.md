# IDA7.2

IDA 7.2의 IDAPython과 Hex-Rays decompiler에서 구조체 필드 접근이 나타나는 함수와 디컴파일 코드 줄 번호를 찾습니다. Python 2.7과 호환되는 문법으로 작성했습니다.

## 사용법

1. IDA에서 분석할 IDB를 열고 구조체 타입을 적용합니다.
2. **File > Script file**에서 `find_struct_field_72.py`를 실행합니다.
3. 구조체 타입 이름과 직접 멤버 이름을 입력합니다. 멤버 이름을 비우면 모든 직접 멤버를 찾습니다.

스크립트를 실행한 뒤 Python 콘솔에서도 호출할 수 있습니다.

```python
hits = find_struct_field("MY_STRUCT", "field")
hits = find_struct_field("MY_STRUCT")
# 지정한 함수만 검색할 때:
hits = find_struct_field("MY_STRUCT", "field", function_eas=[0x401000, 0x402000])
```

결과에는 `function_ea`, `function`, `field`, `line`, `access_ea`, `text`가 포함됩니다. `line`은 함수 선언과 지역변수 선언을 포함한 `cfunc.get_pseudocode()`의 **1부터 시작하는 줄 번호**입니다. 타입, 주석, 디컴파일 표시 설정을 바꾸면 줄 번호도 바뀔 수 있습니다. `access_ea`는 대응하는 명령 주소가 없으면 `BADADDR`일 수 있습니다.

## 알고리즘과 성능

- 함수마다 한 번 디컴파일하고 `CV_FAST` visitor로 ctree를 한 번 순회합니다.
- `cot_memref` / `cot_memptr`의 부모 타입과 멤버 오프셋을 비교합니다. Union은 멤버 번호를 비교합니다.
- 일치하는 함수만 pseudocode를 렌더링하고, 색상 태그의 ctree anchor를 한 번 읽어 item index를 줄 번호에 매핑합니다.
- 직접 anchor가 없는 경우 `find_item_coords`를 사용합니다. 매핑할 수 없는 접근도 `line=None`으로 남깁니다.
- 같은 함수 안에서는 타입 비교를 캐시합니다. 취소 및 디컴파일 실패는 출력에 표시합니다.

일반 경로의 비용은 디컴파일 비용 + 전체 ctree 크기 + 일치한 함수의 pseudocode 길이에 비례합니다. `find_item_coords` fallback 비용은 별도입니다. 첫 전체 검색에서는 디컴파일 비용이 가장 큽니다. 반복 검색은 Hex-Rays 자체 캐시를 활용합니다. `function_eas`로 검색 범위를 줄이면 더 빠르지만 지정하지 않은 함수는 검색하지 않습니다. 멤버 xref만으로 후보를 제한하면 디컴파일에서만 인식된 접근을 놓칠 수 있어 기본 검색에서는 사용하지 않습니다.

## 범위와 검증 상태

읽기, 쓰기, 주소 취득을 모두 **필드 사용**으로 포함하며 종류를 구분하지 않습니다. 직접 멤버를 검색하므로 중첩 구조체의 필드는 그 중첩 타입 이름으로 검색해야 합니다. 타입이 적용되지 않은 포인터 산술, 최적화로 제거된 접근, 디컴파일 실패 함수는 찾아낼 수 없습니다. Bitfield 및 겹치는 멤버 오프셋은 지원하지 않습니다.

Python 구문 검사는 통과했습니다. IDA 7.2 실행 환경이 없어 실제 IDB에서의 실행 및 속도는 아직 검증하지 않았습니다. 오래된 SWIG API 바인딩 차이가 있으면 추가 조정이 필요할 수 있습니다.

API 참고: [Hex-Rays ctree 설명](https://hex-rays.com/blog/hex-rays-decompiler-primer), [ctree anchor API](https://python.docs.hex-rays.com/8.4/d5/d2c/classida__hexrays_1_1ctree__anchor__t-members.html), [cfunc API](https://python.docs.hex-rays.com/classida__hexrays_1_1cfunc__t.html). 링크의 API 문서는 7.2 전용 문서가 아닙니다.
