from setuptools import setup, find_packages

from pymusig.version import __version__


setup(
    name="pymusig",
    version=__version__,
    python_requires='>=3.5',
    description="Implementation of the MuSig multisignature protocol for python",
    long_description=open('README.md').read(),
    author="Marcel Bruhn",
    license="MIT",
    include_package_data=True,
    packages=find_packages(exclude=["tests"]),
    install_requires=['chacha20poly1305==0.0.3']
)
