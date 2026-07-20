# Senrigan이란?

## 몇 분 만에 AWS 위협 헌팅 — SIEM 불필요, 클라우드 인프라 불필요
> CloudTrail 로그를 넣기만 하면 바로 실행 가능한 100개 이상의 위협 헌팅, BI 대시보드, AI 보조 분석을 사용할 수 있습니다
> — 모두 단 한 번의 `make up`으로 노트북에서 실행됩니다.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://github.com/Yamato-Security/senrigan/blob/main/LICENSE)
[![CI](https://github.com/Yamato-Security/senrigan/actions/workflows/ci.yml/badge.svg)](https://github.com/Yamato-Security/senrigan/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-compose-blue)](https://github.com/Yamato-Security/senrigan/blob/main/docker/docker-compose.yml)
[![DEFCON](https://img.shields.io/badge/DEFCON-2026-red)](https://defcon.org/html/defcon-34/dc-34-demolabs.html#content_66521)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://github.com/Yamato-Security/senrigan/blob/main/ingester/Cargo.toml)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://github.com/Yamato-Security/senrigan/blob/main/agent/requirements.txt)

## 주요 기능
## 🔍 100개 이상의 내장 헌팅 + AI 채팅

<img src="../assets/img-agent.png" width="800" alt="AI 채팅 UI">

## 📊 80개 이상의 사전 구축된 대시보드 차트

<img src="../assets/img-dashboard.png" width="800" alt="Superset 대시보드">

## 🦅️ Suzaku 결과 시각화

<img src="../assets/img-suzaku-summary.png" width="800" alt="Suzaku 결과 시각화">

## 📄 HTML 위협 헌팅 리포트

<img src="../assets/img-html.png" width="800" alt="HTML 위협 헌팅 리포트">

## 🗺 AWS Config 리소스 그래프

<img src="../assets/img-config.png" width="800" alt="AWS Config 리소스 그래프">

## 대상 사용자
- 🔍 보안 엔지니어 — AWS 계정 침해, 권한 상승, 데이터 유출을 조사하는 분
- 🛡 클라우드 보안 팀 — 전용 SIEM 없이 주기적인 클라우드 보안 태세 검토를 수행하는 분
- 🧑‍💻 개발자 및 SRE — 인시던트 발생 중 또는 이후에 자신의 계정 CloudTrail 기록을 빠르게 감사하는 분

---
