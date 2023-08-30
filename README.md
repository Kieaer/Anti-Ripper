# Anti-Ripper
![GitHub all releases](https://img.shields.io/github/downloads/kieaer/Anti-Ripper/total?style=flat-square)
![GitHub release (latest by date)](https://img.shields.io/github/downloads/kieaer/Anti-Ripper/latest/total?style=flat-square)<br>

리퍼충들의 횡포를 참지 못한 개발자가 만든 리퍼충 감지 프로그램

## 요구 사항

* Windows 10 이상
* [VRCX](https://github.com/vrcx-team/VRCX) 가 설치되어 있어야 합니다. (압축 파일 형태 안됨)

## 사용 방법

* 처음 실행할 때 VRCX 데이터가 많을 경우 장시간 소요될 수 있습니다.
* a 명령어를 입력하여 카운트를 확인합니다.
* 숫자가 높을 수록 리퍼 유저일 확률이 높으며, 2 이상이면 사실상 확정입니다.

## 작동 원리

1. VRChat 계정에 로그인을 하고, VRCX 에서 누락된 user_id 값을 VRChat 서버에서 모두 불러온 후 파일로 저장합니다.<br>
2. 리퍼 스토어에서 뜯긴 시간을 확인하고, VRCX 시간과 비교하여 뜯긴 시간 ±5분동안 입장했던 모든 플레이어들에게 감지 횟수를 부여합니다.
3. 초기 작업이 끝난 이후부터는 실시간으로 감시하게 됩니다.

2번 작업후 카운터가 높은 사람은 리퍼 유저일 확률이 매우 높습니다.