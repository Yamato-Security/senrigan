---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Senrigan](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Senrigan</strong>은 <a href="https://github.com/Yamato-Security">Yamato Security</a>가 만든 <strong>오프라인, 오픈소스 AWS CloudTrail DFIR 및 위협 헌팅
플랫폼</strong>입니다. CloudTrail 로그를 넣기만 하면 <strong>바로 실행 가능한 100여 개의 위협 헌팅</strong>, <strong>80여 개의 Superset
대시보드 차트</strong>, AI 지원 분석, 그리고 AWS Config 리소스 그래프를 — 단 한 번의 <code>make up</code>으로 노트북에서 모두 사용할 수 있습니다. SIEM도 필요 없고, 클라우드 인프라도 필요 없습니다.
</p>

<div class="hb-cta" markdown>
[시작하기 :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[레퍼런스 :material-book-search:](reference/index.md){ .md-button }
[GitHub에서 보기 :fontawesome-brands-github:](https://github.com/Yamato-Security/senrigan){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/senrigan/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/senrigan?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/senrigan/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/senrigan?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/senrigan/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPLv3-blue.svg?style=flat"/></a>
<a href="https://github.com/Yamato-Security/senrigan/blob/main/docker/docker-compose.yml"><img src="https://img.shields.io/badge/docker-compose-blue"></a>
<a href="https://defcon.org/html/defcon-34/dc-34-demolabs.html#content_66521"><img src="https://img.shields.io/badge/DEFCON-2026-red"></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## 왜 Senrigan인가?

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __오프라인 및 자체 완결형__

    ---

    단 한 번의 `make up`으로 노트북에서 완전히 실행됩니다 — **SIEM도, 클라우드 인프라도 필요 없습니다**.

-   :material-target:{ .lg .middle } __100여 개의 내장 헌팅__

    ---

    침해, 권한 상승, 데이터 유출을 다루는 바로 실행 가능한 AWS CloudTrail 위협 헌팅입니다.

-   :material-robot:{ .lg .middle } __AI 채팅 분석__

    ---

    AI 지원 분석으로 CloudTrail 데이터를 자연어로 조사하세요.

-   :material-chart-box:{ .lg .middle } __80여 개의 대시보드 차트__

    ---

    활동을 한눈에 시각화하는 사전 구축된 Apache **Superset** BI 대시보드입니다.

-   :material-file-document:{ .lg .middle } __리포트 및 Suzaku__

    ---

    HTML 위협 헌팅 리포트를 생성하고 [Suzaku](https://github.com/Yamato-Security/suzaku) 결과를 시각화하세요.

-   :material-graph:{ .lg .middle } __AWS Config 리소스 그래프__

    ---

    계정의 리소스와 그 관계를 그래프로 탐색하세요.

</div>

## 빠른 링크

<div class="grid cards" markdown>

-   __:material-book-open-variant: 처음이신가요?__

    [개요](overview/index.md)에서 시작한 다음,
    [시작하기](getting-started/index.md)로 이동하여 Docker로 실행해 보세요.

-   __:material-book-search-outline: 헌팅이나 차트를 찾고 계신가요?__

    [내장 쿼리 및 대시보드 레퍼런스](reference/index.md)를 살펴보세요 — 100여 개의 헌팅과 80여 개의 차트가 있습니다.

-   __:material-puzzle: 더 깊이 알고 싶으신가요?__

    플랫폼의 [모듈](overview/modules.md)과 [아키텍처](overview/architecture.md)를 확인하세요.

</div>
