# 시작하기

## 사전 요구 사항

| 요구 사항                              | 세부 정보                                          |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop 또는 Docker Engine + Compose v2     |
| **make**                              | GNU Make (macOS에는 기본 설치됨)                    |
| **Resources**                         | 최소 16 GB RAM, SSD 권장                            |
| **CloudTrail logs**                   | AWS에서 내보낸 `.json` 또는 `.json.gz` 파일         |
| *(Optional)* **AWS Config snapshots** | AWS 리소스 그래프용 `.json` 또는 `.json.gz` 파일    |
| *(Optional)* **OpenAI API key**       | AI 쿼리 생성에 필요                                 |
| *(Optional)* **MaxMind GeoLite2**     | GeoIP 보강용 `.mmdb` 파일                           |

---

## 빠른 시작

**1단계.** S3에서 CloudTrail 로그를 다운로드합니다.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**2단계.** 저장소를 복제하고 데이터를 배치합니다.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

아래 두 개의 선택 디렉터리는 자동으로 감지됩니다. 다음 단계 **전에** 파일을 배치하세요. 추가 명령은 필요 없습니다.

| 디렉터리 | 배치할 파일 | 추가되는 기능 |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | 소스 IP를 국가, 도시, ASN으로 변환합니다 |
| `docker/data/config-snapshots/` | AWS Config 스냅샷 `.json` 파일 | AWS Config 리소스 그래프를 생성합니다 |

**3단계.** 로그를 수집하고 서비스를 시작합니다.

```bash
make ingest
make up
```

**4단계.** 🪽 브라우저를 열고 헌팅을 시작하세요!🪽

- http://localhost:8501 — 내장 쿼리 및 AI Chat
- http://localhost:8088 — 대시보드 (`admin` / `admin`)
- http://localhost:8502 — AWS Config 리소스 그래프

---

## 자주 쓰는 명령

인수 없이 `make`를 실행하면 이 목록이 출력됩니다. 모든 타깃은 `make help-all`로 확인할 수 있습니다.

| 명령 | 설명 |
|---|---|
| `make ingest` | `docker/logs/`의 CloudTrail 로그를 DuckDB로 수집 |
| `make up` | UI, 대시보드, 리소스 그래프 시작 |
| `make down` | 모두 중지 |
| `make logs` | 서비스 로그 확인 (하나만 보려면 `SERVICE=agent`) |
| `make reset` | 데이터베이스를 삭제하고 처음부터 다시 시작 |

---

## 기업 프록시 / 사용자 지정 CA 인증서

TLS 검사를 수행하는 기업 프록시 뒤에 있는 경우, 설정 방법은 [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate)를 참조하세요.
