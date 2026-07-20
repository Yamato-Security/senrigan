---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Senrigan](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Senrigan</strong> သည် <a href="https://github.com/Yamato-Security">Yamato Security</a> မှ ဖန်တီးထားသော <strong>အော့ဖ်လိုင်း၊ open-source AWS CloudTrail DFIR နှင့် threat hunting platform</strong> တစ်ခုဖြစ်သည်။ သင်၏ CloudTrail logs များကို ထည့်သွင်းလိုက်ရုံဖြင့် <strong>လက်ငင်းအသုံးပြုနိုင်သော threat hunts ၁၀၀+</strong>၊ <strong>Superset dashboard charts ၈၀+</strong>၊ AI-အကူအညီပါ ခွဲခြမ်းစိတ်ဖြာမှု နှင့် AWS Config resource graph တို့ကို ရရှိမည်ဖြစ်ပြီး — ၎င်းအားလုံးကို သင်၏ laptop ပေါ်တွင် <code>make up</code> တစ်ကြောင်းတည်းဖြင့် လုပ်ဆောင်နိုင်သည်။ SIEM မလိုအပ်ပါ၊ cloud infrastructure လည်း မလိုအပ်ပါ။
</p>

<div class="hb-cta" markdown>
[စတင်ရန် :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[ကိုးကားချက် :material-book-search:](reference/index.md){ .md-button }
[GitHub တွင် ကြည့်ရှုရန် :fontawesome-brands-github:](https://github.com/Yamato-Security/senrigan){ .md-button }
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

## Senrigan ကို ဘာကြောင့် ရွေးချယ်သင့်သနည်း။

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __အော့ဖ်လိုင်း & ကိုယ်ပိုင်လုံလောက်မှု__

    ---

    သင်၏ laptop ပေါ်တွင် `make up` တစ်ကြောင်းတည်းဖြင့် အပြည့်အဝ လုပ်ဆောင်သည် — **SIEM မလို၊ cloud infrastructure မလို**။

-   :material-target:{ .lg .middle } __built-in hunts ၁၀၀+__

    ---

    compromise, privilege escalation နှင့် exfiltration တို့ကို ခြုံငုံလွှမ်းခြုံထားသော လက်ငင်းအသုံးပြုနိုင်သည့် AWS CloudTrail threat hunts များ။

-   :material-robot:{ .lg .middle } __AI chat ခွဲခြမ်းစိတ်ဖြာမှု__

    ---

    သင်၏ CloudTrail data ကို AI-အကူအညီပါ ခွဲခြမ်းစိတ်ဖြာမှုဖြင့် သဘာဝဘာသာစကားဖြင့် စုံစမ်းစစ်ဆေးပါ။

-   :material-chart-box:{ .lg .middle } __dashboard charts ၈၀+__

    ---

    လှုပ်ရှားမှုများကို တစ်ချက်ကြည့်ရှုရုံဖြင့် မြင်သာစေရန် ကြိုတင်တည်ဆောက်ထားသော Apache **Superset** BI dashboards များ။

-   :material-file-document:{ .lg .middle } __အစီရင်ခံစာများ & Suzaku__

    ---

    HTML threat-hunting အစီရင်ခံစာများ ထုတ်လုပ်ပြီး [Suzaku](https://github.com/Yamato-Security/suzaku) ၏ ရလဒ်များကို မြင်သာအောင် ပြသပါ။

-   :material-graph:{ .lg .middle } __AWS Config resource graph__

    ---

    သင်၏ အကောင့်ရှိ resources များနှင့် ၎င်းတို့၏ ဆက်နွှယ်မှုများကို graph အဖြစ် လေ့လာပါ။

</div>

## အမြန်လင့်ခ်များ

<div class="grid cards" markdown>

-   __:material-book-open-variant: ဒီကို အသစ်ရောက်လာတာလား။__

    [အကျဉ်းချုပ်](overview/index.md) ဖြင့် စတင်ပြီးနောက် Docker ဖြင့် စတင်လုပ်ဆောင်ရန် [စတင်ခြင်း](getting-started/index.md) သို့ ဆက်သွားပါ။

-   __:material-book-search-outline: hunt သို့မဟုတ် chart ရှာဖွေနေပါသလား။__

    [Built-in Query & Dashboard Reference](reference/index.md) ကို လှန်လှောကြည့်ပါ — hunts ၁၀၀+ နှင့် charts ၈၀+။

-   __:material-puzzle: ပိုမိုဆက်လက်လေ့လာလိုပါသလား။__

    platform ၏ [Modules](overview/modules.md) နှင့် [Architecture](overview/architecture.md) ကို ကြည့်ရှုပါ။

</div>
