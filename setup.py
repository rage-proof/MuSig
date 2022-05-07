from setuptools import setup, find_packages
from pymusig.version import __version__

import pathlib
HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="pymusig",
    version=__version__,
    python_requires='>=3.5',
    description="Implementation of the MuSig2 multi-signature protocol for python",
    long_description=README,
    long_description_content_type="text/markdown",
    author="rage-proof",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    include_package_data=True,
    packages=find_packages(exclude=["tests"]),
    install_requires=['chacha20poly1305==0.0.3']
)
