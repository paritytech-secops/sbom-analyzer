# SBOM Analyzer

A Python tool for analyzing Software Bill of Materials (SBOM) files and enriching them with metadata from package registries.

## Features

- Parses SBOM files and extracts package information
- Retrieves additional metadata for packages including:
  - Repository URL and owner information
  - Package maintainers/owners
  - Download statistics (last 7 days)
  - Latest package push date and author
- Currently supports:
  - Cargo (Rust) packages via crates.io API
- Planned support:
  - npm (JavaScript/Node.js) packages
  - PyPI (Python) packages

## Installation

Use Python 3.10 or higher and virtualenv to create a virtual environment, then install the requirements:

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
