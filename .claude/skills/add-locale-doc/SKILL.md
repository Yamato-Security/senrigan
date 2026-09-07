---
name: add-locale-doc
description: Ship a user-facing documentation change across every locale of the MkDocs site. Use when adding or changing a page under website/docs/, because a locale left behind silently serves English instead of failing.
---

# Shipping a site page in every locale

`website/docs/` is the product; `doc/` is internal. A user-facing change is not done until the
page exists in every locale the site builds, because a missing translation does not error — the
site quietly falls back to English and looks up to date.

## The locales

`website/mkdocs.yml` owns the list; nothing else may restate it.

```bash
grep -n 'locale:' website/mkdocs.yml     # the default locale is the first entry
```

Pages are named `<page>.md` for the default locale and `<page>.<locale>.md` for the rest, in the
same directory (`website/docs/reference/index.ja.md`, and so on).

## What stays in English

Chart names, hunt labels and command names are not translated — `tests/test_doc_counts.py` checks
every locale against the same catalogues, so a translated label fails the suite. Translate the
prose around them.

## Verify

```bash
make test-repo    # locale coverage, per-locale counts and name lists
```

The failure names the locale and the stale sentence.
