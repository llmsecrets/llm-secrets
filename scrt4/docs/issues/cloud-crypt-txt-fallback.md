# Issue: cloud-crypt — text-fallback for unsupported file types

**Status:** open, not yet implemented
**Module:** `cloud-crypt`
**Filed:** 2026-04-17

## Problem

Some files can't be passed through scrt4's encryption pipeline as-is:

- Binaries whose on-disk format breaks assumptions in the encrypt-folder
  flow (or simply produce poor compression / metadata artifacts).
- Files that exceed an internal size threshold.
- Proprietary container formats where the semantic content is a small
  amount of text wrapped in a lot of structure the user doesn't need.
- Files the user wants encrypted as *content* but doesn't need to round-trip
  byte-for-byte (notes, transcripts, exported chat logs, etc.).

This limits how much of a user's real Drive footprint `cloud-crypt` can
cover end-to-end.

## Proposed fix

Add a **text-fallback preprocessing step** to `cloud-crypt` (or to a
shared helper that `encrypt-folder` can also call):

1. When a file is added to a batch for encryption, classify it.
2. If the file is in a set of "always convertible" types (PDF, DOCX,
   ODT, RTF, PPTX, HTML, MHTML, EML, IPYNB, some chat-export formats,
   images with OCR, etc.) OR if the raw-encrypt pipeline would reject
   it, convert it to a canonical `.txt` representation.
3. Encrypt the `.txt` representation instead of (or alongside) the
   original.
4. Record the conversion in inventory metadata so a later decrypt
   knows it's looking at a text extract, not the original file.

## Notes

- Josh has prior work on the text-conversion side of this from another
  project — bring that in when starting implementation rather than
  reinventing the converter matrix.
- Conversion lives **outside** the TCB — it's just `cloud-crypt`
  preprocessing. The Core daemon still only sees the thing the module
  hands it to encrypt.
- Keep the decision explicit (flag like `--text-fallback` or a config
  entry), not implicit. The user should always know whether they're
  archiving the original bytes or an extract.
- Round-tripping is out of scope for v1 of the fallback — this is a
  one-way "archive the content" path.

## Promote to GH issue

When the scrt4 issue tracker is the source of truth for this roadmap,
copy this file's body into a real issue, close this placeholder, and
link the issue number from the tracking task (#35).
