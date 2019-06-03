from distutils.core import setup

setup(
    name='cyhy-feeds',
    version='0.0.2',
    author="Cyber and Infrastructure Security Agency",
    author_email="ncats@hq.dhs.gov",
    packages=[],  # TODO
    scripts=[],  # TODO
    # NCATS "homepage"
    url="https://www.us-cert.gov/resources/ncats",
    license="License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    description="Data feed components for Cyber Hygiene",
    # long_description=open('README.txt').read(),
    install_requires=[
        "pymongo >= 2.9.2, < 3",
        "python-dateutil >= 2.2",
        "netaddr >= 0.7.10",
        "docopt >= 0.6.2",
        "boto3 >= 1.8.7",
        "python-gnupg >= 0.4.3",
        "requests >= 2.18.4",
        "requests-aws4auth >= 0.9"
    ]
)
