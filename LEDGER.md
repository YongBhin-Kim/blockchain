# Findings 원장 (Vulnerability Ledger)

> 강의 원칙 #4 "상태는 대화가 아닌 파일에 기록하라"의 보안 버전.
> 스캔이 끝날 때마다 finding을 여기에 옮겨 적고 상태를 갱신한다.
> 상태 흐름: `detected → validated → patched → verified` (또는 `false-positive`)

| ID | 파일:라인 | CWE | 심각도 | 상태 | PoC 검증 | PR | 비고 |
|------|--------------|---------|--------|------|----------|------|------|
| F-001 | app.py:30 | CWE-89 (SQLi) | High | detected | - | - | /search 쿼리 조합 |
| F-002 | app.py:39 | CWE-78 (cmd inj) | Critical | detected | - | - | /ping shell=True |
| F-003 | app.py:48 | CWE-22 (path traversal) | High | detected | - | - | /download |
| F-004 | app.py:24 | CWE-798 (secret) | Med | detected | - | - | 하드코딩 키 |
| F-005 | app.py:54 | CWE-916 (weak hash) | Med | detected | - | - | md5 비밀번호 |
| F-006 | app.py:61 | CWE-489 (debug RCE) | High | detected | - | - | debug=True |

## 실습 체크 (한 finding을 끝까지)

- [ ] 스캐너가 탐지했는가? (Findings 뷰에서 확인)
- [ ] 제품이 PoC로 검증했는가? (재현 결과·exit code·산출물 확인)
- [ ] 제안된 최소 패치가 근본 원인을 고치는가? (억제·우회가 아닌지)
- [ ] PR 생성 후 재스캔 시 finding이 사라지는가?
- [ ] criticality를 조정해 모델 피드백을 줬는가?
