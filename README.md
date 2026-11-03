# KeepTrace Framework

**Digital Forensics & Cyber Defense**  
Created by Riyad Alshehri

نسخة أولية تعليمية تعمل على Linux، وتحتوي على:

- قائمة تصنيفات التحقيق الجنائي الرقمي.
- كتالوج أدوات رسمية ثابت داخل المشروع.
- Tool Manager لفحص وتثبيت الأدوات الرسمية.
- Custom Tools محلية لكل مستخدم في `~/.keeptrace/custom_tools`.
- Case Workspace للقضايا والأدلة وSHA-256.
- Activity Log تلقائي.
- Extracted Findings وإخراج Timeline بصيغتي CSV وJSON.
- فحص سلامة ملفات المشروع عبر `security/manifest.json`.

## التشغيل

```bash
cd /path/to/keeptrace
chmod +x keeptrace keeptrace.py
mkdir -p ~/.local/bin
ln -sf "$PWD/keeptrace" ~/.local/bin/keeptrace
keeptrace
```

إذا لم يكن `~/.local/bin` ضمن `PATH`، نفّذ مرة واحدة:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

بعد ذلك يكفي كتابة `keeptrace` من أي مجلد.

> لا يتم تثبيت الأدوات تلقائيًا دون عرض الأمر وطلب موافقة المستخدم. الأدوات المخصصة لا تُثبت تلقائيًا، ولا تدخل في الكتالوج الرسمي.

## بيانات المستخدم

تحفظ خارج المشروع داخل:

```text
~/.keeptrace/
├── cases/
├── custom_tools/
└── logs/
```

نتائج الأدوات تحفظ أولًا داخل `tool_output/` كتحليلات. يمكن مراجعتها من
`View Tool Runs` ثم اختيار `Promote Result to Evidence` فقط إذا قرر المحقق اعتمادها كدليل.

## الحالة الحالية

هذه MVP للبناء والتجربة، وليست إصدارًا جاهزًا للنشر. قبل GitHub يجب إنشاء توقيع إصدار رسمي، ومراجعة كل أمر تثبيت وتعريف أداة، وتشغيل اختبارات أمنية إضافية.
