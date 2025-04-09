# tatrapayplus-python

[![Release](https://img.shields.io/github/v/release/SmartBase-SK/tatrapayplus-python)](https://img.shields.io/github/v/release/SmartBase-SK/tatrapayplus-python)
[![Build status](https://img.shields.io/github/actions/workflow/status/SmartBase-SK/tatrapayplus-python/main.yml?branch=main)](https://github.com/SmartBase-SK/tatrapayplus-python/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/SmartBase-SK/tatrapayplus-python/branch/main/graph/badge.svg)](https://codecov.io/gh/SmartBase-SK/tatrapayplus-python)
[![Commit activity](https://img.shields.io/github/commit-activity/m/SmartBase-SK/tatrapayplus-python)](https://img.shields.io/github/commit-activity/m/SmartBase-SK/tatrapayplus-python)
[![License](https://img.shields.io/github/license/SmartBase-SK/tatrapayplus-python)](https://img.shields.io/github/license/SmartBase-SK/tatrapayplus-python)

# Tatrapay+ python SDK

Source repository for python package for Tatrapay+ payment gateway.

Types of application are generated automatically from swagger structure via [openapi-python-client](https://github.com/openapi-generators/openapi-python-client).

# Type generation

To generate new types after OpenAPI structure has been changed please run
```
openapi-python-client generate --path tatrapayplus_api_sandbox.json --output-path tatrapayplus_client
python3 after_generator.py
```