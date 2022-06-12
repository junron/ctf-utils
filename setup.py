from setuptools import setup, find_packages

setup(name='ctflib',
      version='4.0.2',
      description='[PRIVATE] Tools for speeding up CTFing',
      author='jro',
      install_requires=["z3-solver", "aiohttp", "requests", "pwntools", "click"],
      entry_points={
            'console_scripts': [
                  'ctf = ctflib.scripts.main:cli',
            ],
      },
      packages=find_packages())
