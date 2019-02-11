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
        "cyhy-core >= 0.0.2",
        "python-dateutil >= 2.2",
        "docopt >= 0.6.2",
	"boto3 >= 1.8.7",
        "python-gnupg >= 0.4.3",
        "requests >= 2.18.4",
        "requests-aws4auth >= 0.9"
    ]
)
