from setuptools import setup

setup(name='ctflib',
      version='0.1',
      description='[PRIVATE] Tools for speeding up CTFing',
      author='jro',
      install_requires=["z3-solver", "aiohttp", "requests", "beautifulsoup4"],
      packages=['ctflib'])