from distutils.core import setup

setup(
    name='cyhy-feeds',
    version='0.0.2',
    author='David Redmin',
    author_email='david.redmin@hq.dhs.gov',
    packages=[], #TODO
    scripts=[], #TODO
    #url='http://pypi.python.org/pypi/CyHy/',
    license='LICENSE.txt',
    description='Data feed components for Cyber Hygiene',
    #long_description=open('README.txt').read(),
    install_requires=[
        "cyhy-core >= 0.0.2",
        "python-dateutil >= 2.2",
        "docopt >= 0.6.2",
    ]
)
