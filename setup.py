"""setup.py file."""

from setuptools import setup, find_packages

__author__ = 'Alcatel Lucent Enterprise <ebg_global_supportcenter@al-enterprise.com>'


with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

setup(
    name="napalm-aos",
    version="0.1.1",
    packages=find_packages(),
    author="Alcatel Lucent Enterprise",
    author_email="ebg_global_supportcenter@al-enterprise.com",
    zip_safe=False,
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-aos",
    include_package_data=True,
    install_requires=reqs,
)
