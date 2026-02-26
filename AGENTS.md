# Agent Guidelines

## Temporary files

Temporary files (screenshots, traces, recordings, etc.) must be stored in `tmp/`. This directory is gitignored. Never write temporary files to the project root or other directories.

```bash
curl -s --proxy http://127.0.0.1:8080 -k https://example.com > tmp/response.html
playwright-cli -s=proxy screenshot --filename=tmp/screenshot.png
```
