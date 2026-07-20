---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Senrigan](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Senrigan</strong> هي <strong>منصة غير متصلة بالإنترنت ومفتوحة المصدر لتحليل الأدلة الجنائية الرقمية والاستجابة للحوادث (DFIR) وتعقّب التهديدات على AWS CloudTrail</strong> من إعداد <a href="https://github.com/Yamato-Security">Yamato Security</a>. أدخِل سجلّات
CloudTrail الخاصة بك واحصل على <strong>أكثر من 100 عملية تعقّب للتهديدات جاهزة للتشغيل</strong>، و<strong>أكثر من 80 مخطط لوحة معلومات Superset</strong>، وتحليل مدعوم بالذكاء الاصطناعي ورسم بياني لموارد AWS Config — كل ذلك على
حاسوبك المحمول بأمر <code>make up</code> واحد. لا حاجة إلى SIEM، ولا حاجة إلى بنية تحتية سحابية.
</p>

<div class="hb-cta" markdown>
[ابدأ الآن :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[المرجع :material-book-search:](reference/index.md){ .md-button }
[عرض على GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/senrigan){ .md-button }
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

## لماذا Senrigan؟

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __غير متصلة بالإنترنت ومكتفية ذاتيًا__

    ---

    تعمل بالكامل على حاسوبك المحمول بأمر `make up` واحد — **لا SIEM، ولا بنية تحتية سحابية**.

-   :material-target:{ .lg .middle } __أكثر من 100 عملية تعقّب مدمجة__

    ---

    عمليات تعقّب تهديدات AWS CloudTrail جاهزة للتشغيل تغطي الاختراق وتصعيد الامتيازات وتسريب البيانات.

-   :material-robot:{ .lg .middle } __تحليل عبر محادثة بالذكاء الاصطناعي__

    ---

    حلِّل بيانات CloudTrail الخاصة بك باللغة الطبيعية مع تحليل مدعوم بالذكاء الاصطناعي.

-   :material-chart-box:{ .lg .middle } __أكثر من 80 مخطط لوحة معلومات__

    ---

    لوحات معلومات ذكاء الأعمال (BI) من Apache **Superset** المبنية مسبقًا لتصوّر النشاط بنظرة سريعة.

-   :material-file-document:{ .lg .middle } __التقارير وSuzaku__

    ---

    أنشئ تقارير تعقّب التهديدات بصيغة HTML وصوّر نتائج [Suzaku](https://github.com/Yamato-Security/suzaku).

-   :material-graph:{ .lg .middle } __رسم بياني لموارد AWS Config__

    ---

    استكشف موارد حسابك والعلاقات بينها كرسم بياني.

</div>

## روابط سريعة

<div class="grid cards" markdown>

-   __:material-book-open-variant: جديد هنا؟__

    ابدأ بـ [نظرة عامة](overview/index.md)، ثم توجّه إلى
    [البدء](getting-started/index.md) لتشغيلها باستخدام Docker.

-   __:material-book-search-outline: تبحث عن عملية تعقّب أو مخطط؟__

    تصفّح [مرجع الاستعلامات ولوحات المعلومات المدمجة](reference/index.md) — أكثر من 100 عملية تعقّب وأكثر من 80 مخططًا.

-   __:material-puzzle: ترغب بالتعمّق أكثر؟__

    اطّلع على [الوحدات](overview/modules.md) و[البنية المعمارية](overview/architecture.md) للمنصة.

</div>
