# Security Policy

## Supported versions

REapk ships on PyPI as [`reapk`](https://pypi.org/project/reapk/). Fixes go into the
latest release, so please upgrade before you report anything.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

Please do not open a public issue, pull request, or discussion for a security
problem. Reporting it in the open before there is a fix leaves users exposed.

Report it privately one of two ways:

- Open a private advisory on GitHub at
  [Security → Report a vulnerability](https://github.com/JRBusiness/REapk/security/advisories/new).
  This keeps the report confidential and keeps the discussion and the fix in one
  place. This is the way I prefer.
- If you cannot use GitHub advisories, contact the maintainer through their
  [GitHub profile](https://github.com/JRBusiness).

A report is easier to act on if it includes:

- the REapk version (`pip show reapk`) and your Python version and OS;
- what the problem is and what an attacker gets out of it;
- the smallest set of steps or a proof of concept that reproduces it;
- the input that triggers it. Do not attach malware or copyrighted APKs. Describe
  the malformed structure, or build a minimal synthetic sample that shows the same
  thing.

### What to expect

I will acknowledge the report within 5 business days and give you an initial
assessment and a severity call within 10. From there we agree on a disclosure
timeline, I publish a fixed release and a GitHub Security Advisory, and you get
credit if you want it.

## Scope

REapk parses and rewrites untrusted, attacker-controlled binary formats: APK and
ZIP archives, `AndroidManifest.xml` and AXML, `resources.arsc`, and DEX bytecode.
The following are in scope:

- a malformed input file that crashes the parser, hangs it, or makes it burn
  unbounded CPU or memory;
- path traversal or arbitrary file write while extracting or repackaging an
  APK/XAPK (zip-slip);
- code execution or command injection, including through the handover to the
  optional external `decode` / `build` tooling;
- a signing or verification flaw that lets a modified APK pass a v2/v3 signature
  check, or that produces incorrectly signed output;
- secret-scanning or recon output that writes data somewhere it should not.

Out of scope:

- bugs in third-party dependencies or in the external `decode` / `build` tools.
  Report those upstream; I will bump the pin once a fix is out.
- running REapk against an APK you are not authorized to analyze or modify. REapk
  is a reverse-engineering and patching tool for software you own or have
  permission to assess.
- a crash that needs a deliberately corrupted input and where REapk already exits
  with a clean, non-exploitable error.

## Safe harbor

I welcome good-faith security research. If you make an honest effort to follow this
policy, avoid privacy violations and data loss, do not disrupt other users, and
give me reasonable time to fix the issue before going public, I will not pursue or
support legal action against you for your research.
