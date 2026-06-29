---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Senrigan](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Senrigan</strong> 是由 <a href="https://github.com/Yamato-Security">Yamato Security</a> 開發的<strong>離線、開放原始碼 AWS CloudTrail DFIR 與威脅獵捕平台</strong>。只要放入您的
CloudTrail 日誌，即可取得<strong>超過 100 種可立即執行的威脅獵捕</strong>、<strong>超過 80 個 Superset
儀表板圖表</strong>、AI 輔助分析以及 AWS Config 資源關係圖 — 全部都能在您的筆電上透過單一指令 <code>make up</code> 完成。無需 SIEM，也不需要任何雲端基礎架構。
</p>

<div class="hb-cta" markdown>
[開始使用 :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[參考資料 :material-book-search:](reference/index.md){ .md-button }
[在 GitHub 上檢視 :fontawesome-brands-github:](https://github.com/Yamato-Security/senrigan){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/senrigan/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/senrigan?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/senrigan/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/senrigan?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/senrigan/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPLv3-blue.svg?style=flat"/></a>
<a href="https://github.com/Yamato-Security/senrigan/blob/main/docker/docker-compose.yml"><img src="https://img.shields.io/badge/docker-compose-blue"></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## 為什麼選擇 Senrigan？

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __離線且自給自足__

    ---

    只要透過單一指令 `make up` 即可完全在您的筆電上執行 — **無需 SIEM、無需雲端基礎架構**。

-   :material-target:{ .lg .middle } __超過 100 種內建獵捕__

    ---

    可立即執行的 AWS CloudTrail 威脅獵捕，涵蓋入侵、權限提升與資料外洩。

-   :material-robot:{ .lg .middle } __AI 對話分析__

    ---

    透過 AI 輔助分析，以自然語言調查您的 CloudTrail 資料。

-   :material-chart-box:{ .lg .middle } __超過 80 個儀表板圖表__

    ---

    預先建置的 Apache **Superset** BI 儀表板，讓您一眼掌握活動概況。

-   :material-file-document:{ .lg .middle } __報告與 Suzaku__

    ---

    產生 HTML 威脅獵捕報告，並將 [Suzaku](https://github.com/Yamato-Security/suzaku) 結果視覺化。

-   :material-graph:{ .lg .middle } __AWS Config 資源關係圖__

    ---

    以關係圖的方式探索您帳戶中的資源及其相互關係。

</div>

## 快速連結

<div class="grid cards" markdown>

-   __:material-book-open-variant: 初次使用？__

    從[總覽](overview/index.md)開始，接著前往
    [開始使用](getting-started/index.md)，以 Docker 啟動它。

-   __:material-book-search-outline: 正在尋找某個獵捕或圖表？__

    瀏覽[內建查詢與儀表板參考資料](reference/index.md) — 超過 100 種獵捕與 80 個圖表。

-   __:material-puzzle: 想更深入了解？__

    請參閱本平台的[模組](overview/modules.md)與[架構](overview/architecture.md)。

</div>
