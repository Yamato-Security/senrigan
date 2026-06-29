---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Senrigan](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Senrigan</strong> は <a href="https://github.com/Yamato-Security">Yamato Security</a> による<strong>オフラインかつオープンソースの AWS CloudTrail DFIR・脅威ハンティング
プラットフォーム</strong>です。CloudTrail
ログを取り込むだけで、<strong>すぐに実行できる 100 以上の脅威ハンティング</strong>、<strong>80 以上の Superset
ダッシュボードチャート</strong>、AI 支援による分析、そして AWS Config リソースグラフが手に入ります。すべてがあなたの
ノートパソコン上で、単一の <code>make up</code> だけで動作します。SIEM は不要、クラウドインフラも不要です。
</p>

<div class="hb-cta" markdown>
[はじめに :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[リファレンス :material-book-search:](reference/index.md){ .md-button }
[GitHub で見る :fontawesome-brands-github:](https://github.com/Yamato-Security/senrigan){ .md-button }
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

## なぜ Senrigan なのか？

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __オフラインで自己完結__

    ---

    単一の `make up` だけであなたのノートパソコン上で完全に動作します — **SIEM 不要、クラウドインフラ不要**。

-   :material-target:{ .lg .middle } __100 以上の組み込みハンティング__

    ---

    侵害、権限昇格、データ持ち出しをカバーする、すぐに実行できる AWS CloudTrail 脅威ハンティング。

-   :material-robot:{ .lg .middle } __AI チャット分析__

    ---

    AI 支援による分析で、CloudTrail データを自然言語で調査できます。

-   :material-chart-box:{ .lg .middle } __80 以上のダッシュボードチャート__

    ---

    あらかじめ用意された Apache **Superset** BI ダッシュボードで、アクティビティをひと目で可視化。

-   :material-file-document:{ .lg .middle } __レポートと Suzaku__

    ---

    HTML 形式の脅威ハンティングレポートを生成し、[Suzaku](https://github.com/Yamato-Security/suzaku) の結果を可視化します。

-   :material-graph:{ .lg .middle } __AWS Config リソースグラフ__

    ---

    アカウントのリソースとその関係性をグラフとして探索できます。

</div>

## クイックリンク

<div class="grid cards" markdown>

-   __:material-book-open-variant: 初めての方は？__

    まず [概要](overview/index.md) から始め、続いて
    [はじめに](getting-started/index.md) で Docker を使って起動してみましょう。

-   __:material-book-search-outline: ハンティングやチャートをお探しですか？__

    [組み込みクエリ・ダッシュボードリファレンス](reference/index.md) をご覧ください — 100 以上のハンティングと 80 以上のチャート。

-   __:material-puzzle: さらに先へ進むには？__

    プラットフォームの [モジュール](overview/modules.md) と [アーキテクチャ](overview/architecture.md) をご確認ください。

</div>
