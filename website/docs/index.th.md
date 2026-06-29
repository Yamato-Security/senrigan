---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![Senrigan](assets/logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>Senrigan</strong> คือ <strong>แพลตฟอร์ม DFIR และการล่าภัยคุกคามสำหรับ AWS CloudTrail แบบออฟไลน์และโอเพนซอร์ส</strong> โดย <a href="https://github.com/Yamato-Security">Yamato Security</a> เพียงนำเข้า
ล็อก CloudTrail ของคุณ แล้วรับ <strong>การล่าภัยคุกคามที่พร้อมใช้งานกว่า 100 รายการ</strong>, <strong>แผนภูมิแดชบอร์ด Superset
กว่า 80 รายการ</strong>, การวิเคราะห์ด้วยความช่วยเหลือจาก AI และกราฟทรัพยากร AWS Config — ทั้งหมดนี้บน
แล็ปท็อปของคุณด้วยคำสั่ง <code>make up</code> เพียงคำสั่งเดียว ไม่ต้องใช้ SIEM ไม่ต้องใช้โครงสร้างพื้นฐานบนคลาวด์
</p>

<div class="hb-cta" markdown>
[เริ่มต้นใช้งาน :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[เอกสารอ้างอิง :material-book-search:](reference/index.md){ .md-button }
[ดูบน GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/senrigan){ .md-button }
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

## ทำไมต้อง Senrigan?

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __ออฟไลน์และครบในตัว__

    ---

    ทำงานทั้งหมดบนแล็ปท็อปของคุณด้วยคำสั่ง `make up` เพียงคำสั่งเดียว — **ไม่ต้องใช้ SIEM ไม่ต้องใช้โครงสร้างพื้นฐานบนคลาวด์**

-   :material-target:{ .lg .middle } __การล่าภัยคุกคามในตัวกว่า 100 รายการ__

    ---

    การล่าภัยคุกคาม AWS CloudTrail ที่พร้อมใช้งาน ครอบคลุมการถูกบุกรุก การยกระดับสิทธิ์ และการขโมยข้อมูลออก

-   :material-robot:{ .lg .middle } __การวิเคราะห์ด้วยแชต AI__

    ---

    สืบสวนข้อมูล CloudTrail ของคุณด้วยภาษาธรรมชาติผ่านการวิเคราะห์ด้วยความช่วยเหลือจาก AI

-   :material-chart-box:{ .lg .middle } __แผนภูมิแดชบอร์ดกว่า 80 รายการ__

    ---

    แดชบอร์ด BI ของ Apache **Superset** ที่สร้างไว้ล่วงหน้า เพื่อมองเห็นกิจกรรมได้ในพริบตา

-   :material-file-document:{ .lg .middle } __รายงานและ Suzaku__

    ---

    สร้างรายงานการล่าภัยคุกคามแบบ HTML และแสดงผลลัพธ์ของ [Suzaku](https://github.com/Yamato-Security/suzaku)

-   :material-graph:{ .lg .middle } __กราฟทรัพยากร AWS Config__

    ---

    สำรวจทรัพยากรในบัญชีของคุณและความสัมพันธ์ระหว่างกันในรูปแบบกราฟ

</div>

## ลิงก์ด่วน

<div class="grid cards" markdown>

-   __:material-book-open-variant: เพิ่งเริ่มต้นใช่ไหม?__

    เริ่มจาก [ภาพรวม](overview/index.md) จากนั้นไปยัง
    [การเริ่มต้นใช้งาน](getting-started/index.md) เพื่อเริ่มรันด้วย Docker

-   __:material-book-search-outline: กำลังมองหาการล่าภัยคุกคามหรือแผนภูมิ?__

    เรียกดู [เอกสารอ้างอิงคิวรีและแดชบอร์ดในตัว](reference/index.md) — การล่าภัยคุกคามกว่า 100 รายการและแผนภูมิกว่า 80 รายการ

-   __:material-puzzle: ต้องการเรียนรู้เพิ่มเติม?__

    ดู [โมดูล](overview/modules.md) และ [สถาปัตยกรรม](overview/architecture.md) ของแพลตฟอร์ม

</div>
