# tatrapayplus-python

[![Release](https://img.shields.io/github/v/release/tatrabanka/tatrapayplus-python)](https://img.shields.io/github/v/release/tatrabanka/tatrapayplus-python)
[![Build status](https://img.shields.io/github/actions/workflow/status/tatrabanka/tatrapayplus-python/main.yml?branch=main)](https://github.com/tatrabanka/tatrapayplus-python/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/tatrabanka/tatrapayplus-python/branch/main/graph/badge.svg)](https://codecov.io/gh/tatrabanka/tatrapayplus-python)
[![Commit activity](https://img.shields.io/github/commit-activity/m/tatrabanka/tatrapayplus-python)](https://img.shields.io/github/commit-activity/m/tatrabanka/tatrapayplus-python)
[![License](https://img.shields.io/github/license/tatrabanka/tatrapayplus-python)](https://img.shields.io/github/license/tatrabanka/tatrapayplus-python)

Python package for Tatrapay+ payment gateway.

- **Github repository**: <https://github.com/tatrabanka/tatrapayplus-python/>
- **Documentation** <https://sdk.tatrabanka.sk/docs/libraries/python/v1.0.0>

## Type generation
To generate new types after OpenAPI structure has been changed please run
```
openapi-python-client generate --path tatrapayplus_api_sandbox.json --output-path tatrapayplus_client
./after_generator.py
```
