"""
This is the setup module for cyhy-feeds.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
- https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
"""

from setuptools import setup, find_packages
from glob import glob
from os.path import splitext, basename


def readme():
    """Read in and return the contents of the project's README.md file."""
    with open("README.md") as f:
        return f.read()


def package_vars(version_file):
    """Read in and return the variables defined by the version_file."""
    pkg_vars = {}
    with open(version_file) as f:
        exec(f.read(), pkg_vars)  # nosec
    return pkg_vars


setup(
    name="cyhy-feeds",
    version=package_vars("aws_jobs/_version.py")["__version__"],
    author="Cyber and Infrastructure Security Agency",
    author_email="ncats@hq.dhs.gov",
    scripts=[],  # TODO
    url="https://www.us-cert.gov/resources/ncats",
    download_url="https://github.com/cisagov/cyhy-feeds",
    license="License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    description="Data feed components for Cyber Hygiene",
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 5 - Production/Stable",
        # Indicate who your project is intended for
        "Intended Audience :: Developers",
        # Pick your license as you wish (should match "license" above)
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
    ],
    # What does your project relate to?
    keywords="cyhy",
    packages=find_packages(where="aws_jobs"),
    package_dir={"": "aws_jobs"},
    package_data={"example": ["data/*.txt"]},
    py_modules=[splitext(basename(path))[0] for path in glob("aws_jobs/*.py")],
    include_package_data=True,
    install_requires=[
        "boto3 >= 1.8.7",
        "botocore >= 1.11.7",
        "docopt >= 0.6.2",
        "mongo-db-from-config >= 0.0.1",
        "netaddr >= 0.7.10",
        "python-dateutil >= 2.2",
        "python-gnupg >= 0.4.3",
        "requests >= 2.18.4",
        "requests-aws4auth >= 0.9",
    ],
    extras_require={"test": ["pre-commit", "pytest", "pytest-cov", "coveralls"]},
)
