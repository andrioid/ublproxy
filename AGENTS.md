# Agent Guidelines

## Temporary files

Temporary files (screenshots, traces, recordings, etc.) must be stored in `tmp/`. This directory is gitignored. Never write temporary files to the project root or other directories.

```bash
playwright-cli -s=proxy screenshot --filename=tmp/screenshot.png
```
