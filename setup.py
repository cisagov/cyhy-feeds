"""
This is the setup module for cyhy-feeds.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
- https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
"""

from setuptools import setup


def readme():
    """Read in and return the contents of the project's README.md file."""
    with open("README.md") as f:
        return f.read()


setup(
    name="cyhy-feeds",
    version="0.0.2",
    author="Cyber and Infrastructure Security Agency",
    author_email="ncats@hq.dhs.gov",
    packages=[],  # TODO
    scripts=[],  # TODO
    url="https://www.us-cert.gov/resources/ncats",
    download_url="https://github.com/cisagov/cyhy-feeds",
    license="License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    description="Data feed components for Cyber Hygiene",
    long_description=readme(),
    long_description_content_type="text/markdown",
    install_requires=[
        "boto3 >= 1.8.7",
        "docopt >= 0.6.2",
        "mongo-db-from-config >= 0.0.1",
        "netaddr >= 0.7.10",
        "pymongo >= 3.7.2",
        "python-dateutil >= 2.2",
        "python-gnupg >= 0.4.3",
        "requests >= 2.18.4",
        "requests-aws4auth >= 0.9",
    ],
    extras_require={"test": ["pre-commit", "pytest", "pytest-cov", "coveralls"]},
)
