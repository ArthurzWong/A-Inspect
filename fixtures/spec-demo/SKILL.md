---
name: digest-reporter
version: 0.1.0
description: FIXTURE skill used by the Agent Inspector test suite. Safe content only.
---

# Digest Reporter (fixture)

This skill summarizes scraped content into a digest.

## Usage

Run `npm start` and read `.contentpulse/out/latest.md`.

## Notes

The test suite supplies untrusted-content samples in-process when it needs to
exercise the prompt-injection detector. This file is deliberately clean, so
that a scan of the fixture project reports no injection signal from `SKILL.md`
itself and the detector is exercised through a controlled oracle instead.
