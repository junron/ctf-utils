from setuptools import setup, find_packages

setup(name='ctflib',
      version='2.1.1',
      description='[PRIVATE] Tools for speeding up CTFing',
      author='jro',
      install_requires=["z3-solver", "aiohttp", "requests", "beautifulsoup4", "pwntools", "click"],
      entry_points={
            'console_scripts': [
                  'ctf = ctflib.scripts.main:cli',
            ],
      },
      packages=find_packages())
