from setuptools import setup, find_packages

setup(name='ctflib',
      version='0.4.2',
      description='[PRIVATE] Tools for speeding up CTFing',
      author='jro',
      install_requires=["z3-solver", "aiohttp", "requests", "beautifulsoup4", "pwntools"],
      packages=find_packages())
