import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='iocextract',
    version='1.7.2',
    include_package_data=True,
    py_modules=[
        'iocextract',
    ],
    install_requires=[
        'regex',
    ],
    extras_require={
        ':python_version <= "2.7"': [
            'ipaddress',
        ],
    },
    entry_points={
          'console_scripts': [
              'iocextract = iocextract:main'
          ]
    },
    license='BSD',
    description='Advanced Indicator of Compromise (IOC) extractor.',
    long_description=README,
    url='https://github.com/InQuest/python-iocextract',
    author='InQuest Labs',
    author_email='labs@inquest.net',
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: Internet',
    ],
)
