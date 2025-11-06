#!/usr/bin/env python3
"""Setup script."""
import os

from setuptools import setup


def open_file(fname):
    """Open and return a file-like object for the relative filename."""
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name="azul-plugin-script-decoder",
    description="Decodes scripts encoded using Microsoft's screnc.exe tool",
    author="Azul",
    author_email="azul@asd.gov.au",
    url="https://www.asd.gov.au/",
    packages=["azul_plugin_script_decoder"],
    include_package_data=True,
    python_requires=">=3.12",
    classifiers=[],
    entry_points={
        "console_scripts": [
            "azul-plugin-script-decoder = azul_plugin_script_decoder.main:main",
            "pdfid = azul_plugin_script_decoder.didier.pdfid:Main",
            "pdf-parser = azul_plugin_script_decoder.didier.pdf_parser:Main",
            "decode-vbe = azul_plugin_script_decoder.didier.decode_vbe:Main",
        ]
    },
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[r.strip() for r in open_file("requirements.txt") if not r.startswith("#")],
)
