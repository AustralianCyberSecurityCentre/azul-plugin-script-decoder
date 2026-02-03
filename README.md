# Azul Plugin Script Decoder

Plugin for decrypting scripts encoded with Microsoft's screnc.exe tool.

These can be standalone encoded jscript or vbscript (.jse/.vbe extensions
respectively), or embedded within HTML script tags.

## Development Installation

To install azul-plugin-script-decoder for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```
azul-plugin-script-decoder malware.file
```

Example Output:

```
----- ScriptDecoder results -----
OK

Output features:
  tag: encoded_script

Feature key:
  tag:  Any informational label about the sample

Generated child entities (1):
  {'action': 'decoded', 'offset': '0x30', 'language': 'jscript'} <binary: bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615>
    content: 516943 bytes
```

Automated usage in system:

```
azul-plugin-script-decoder --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
