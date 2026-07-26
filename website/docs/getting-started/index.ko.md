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

**2단계.** 저장소를 복제하고, 로그를 수집하고, 모든 서비스를 시작합니다.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded logs into the Docker logs directory
cp -r <local-output-dir>/ docker/logs/

# Ingest CloudTrail logs into DuckDB
make ingest

# Start all services (agent + dashboard)
make up
```

**3단계.** 🪽 브라우저를 열고 헌팅을 시작하세요!🪽

- http://localhost:8501 — 내장 쿼리 및 AI Chat
- http://localhost:8088 — 대시보드 (`admin` / `admin`)
- http://localhost:8502 — AWS Config 리소스 그래프

**(선택 사항)** GeoIP 보강.
[GeoLite2 `.mmdb` 파일](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)을 `docker/data/geoip/`에 배치한 다음:

```bash
make ingest-geoip
```

**(선택 사항)** 리소스 그래프 시각화를 위한 AWS Config 스냅샷 수집.
AWS Config 스냅샷 파일을 `docker/data/config-snapshots/`에 배치한 다음:
```bash
make ingest-config
```
---

## 기업 프록시 / 사용자 지정 CA 인증서

TLS 검사를 수행하는 기업 프록시 뒤에 있는 경우, 설정 방법은 [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate)를 참조하세요.
