import os
from setuptools import setup

with open("README.md", "r") as fh:
    README = fh.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='iocextract',
    version='1.16.1',
    include_package_data=True,
    py_modules=['iocextract'],
    install_requires=['regex'],
    extras_require = {
        ':python_version <= "2.7"': [
            'ipaddress',
        ],
    },
    entry_points={
        'console_scripts': [
            'iocextract = iocextract:main'
        ]
    },
    license='GPL',
    description='Advanced Indicator of Compromise (IOC) extractor.',
    long_description=README,
    long_description_content_type = "text/markdown",
    url='https://github.com/InQuest/iocextract',
    author='InQuest Labs',
    author_email='labs@inquest.net',
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: Internet',
    ],
)
