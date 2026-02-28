# Agent Guidelines

## Important workflow

1. Understand the problem. Ask questions
2. Use red/green (tdd). Test must fail before changes are made
3. Always update documentation after making changes

## Temporary files

Temporary files (screenshots, traces, recordings, etc.) must be stored in `tmp/`. This directory is gitignored. Never write temporary files to the project root or other directories.

```bash
curl -s --proxy https://127.0.0.1:8443 --proxy-insecure -k https://example.com > tmp/response.html
playwright-cli -s=proxy screenshot --filename=tmp/screenshot.png
```
