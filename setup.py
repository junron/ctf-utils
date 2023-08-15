from setuptools import setup, find_packages

setup(name='ctflib',
      version='4.6.1',
      description='Tools for speeding up CTFing',
      author='jro',
      install_requires=["z3-solver", "aiohttp", "requests", "pwntools", "click"],
      entry_points={
            'console_scripts': [
                  'ctf = ctflib.scripts.main:cli',
            ],
      },
      package_data={'': ['pwn/dockerfiles/bullseye-2.31','pwn/dockerfiles/docker-compose.yml']},
      include_package_data=True,
      packages=find_packages())
