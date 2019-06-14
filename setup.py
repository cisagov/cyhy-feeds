from distutils.core import setup

setup(
    name='cyhy-feeds',
    version='0.0.2',
    author='Department of Homeland Security, National Cybersecurity Assessments and Technical Services team',
    author_email='ncats@hq.dhs.gov',
    packages=[], #TODO
    scripts=[], #TODO
    #url='http://pypi.python.org/pypi/CyHy/',
    license='LICENSE.txt',
    description='Data feed components for Cyber Hygiene',
    #long_description=open('README.txt').read(),
    install_requires=[
        "boto3 >= 1.8.7",
        "docopt >= 0.6.2",
        "mongo-db-from-config >= 0.0.1",
        "netaddr >= 0.7.10",
        "pymongo >= 2.9.2, < 3",
        "python-dateutil >= 2.2",
        "python-gnupg >= 0.4.3",
        "requests >= 2.18.4",
        "requests-aws4auth >= 0.9"        
    ]
)
