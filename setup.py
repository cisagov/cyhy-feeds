"""
This is the setup module for cyhy-feeds.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
- https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
"""

# Standard Python Libraries
from glob import glob
import io
from os.path import basename, splitext

# Third-Party Libraries
from setuptools import find_packages, setup


def readme():
    """Read in and return the contents of the project's README.md file."""
    # Python 3
    try:
        with open("README.md", encoding="utf-8") as f:
            return f.read()
    # Python 2 fallback
    except TypeError:
        with io.open("README.md", encoding="utf-8") as f:
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
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    # What does your project relate to?
    keywords="cyhy",
    packages=find_packages(where="aws_jobs"),
    package_dir={"": "aws_jobs"},
    py_modules=[splitext(basename(path))[0] for path in glob("aws_jobs/*.py")],
    include_package_data=True,
    install_requires=[
        "boto3 >= 1.8.7",
        "botocore >= 1.11.7",
        "docopt >= 0.6.2",
        "mongo-db-from-config @ https://github.com/cisagov/mongo-db-from-config/tarball/develop#egg=mongo-db-from-config",
        "netaddr >= 0.7.10",
        "python-dateutil >= 2.2, < 3.0.0",
        "python-gnupg >= 0.4.3",
        "pytz",
        "requests >= 2.18.4",
        "requests-aws4auth >= 0.9",
    ],
    extras_require={
        "test": [
            "pre-commit",
            # coveralls 1.11.0 added a service number for calls from
            # GitHub Actions. This caused a regression which resulted in a 422
            # response from the coveralls API with the message:
            # Unprocessable Entity for url: https://coveralls.io/api/v1/jobs
            # 1.11.1 fixed this issue, but to ensure expected behavior we'll pin
            # to never grab the regression version.
            "coveralls != 1.11.0",
            "coverage",
            "pytest-cov",
            "pytest",
        ]
    },
)
