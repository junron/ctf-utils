import os.path
import shutil
from pathlib import Path

import click
from pwnlib.elf import ELF

import ctflib.pwn.template_gen as tg
import ctflib.reversing.z3_gen as z3_gen
import ctflib.web.template_gen as web_tg
from ctflib.pwn.patcher import patch
from ctflib.web.wasabi import init_wasabi
import ctflib.pwn.menu_gen as mg


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.exit()


@cli.command()
@click.option('--remote', '-r', default='', help='remote connection string')
def pwn(remote: str):
    tg.generate_template(remote)


@cli.command()
def z3():
    z3_gen.sym_str_template()


@cli.command()
def docker():
    shutil.copyfile(os.path.join(Path(__file__).parent.parent, "pwn", "dockerfiles", "bullseye-2.31"), "./Dockerfile")
    shutil.copyfile(os.path.join(Path(__file__).parent.parent, "pwn", "dockerfiles", "docker-compose.yml"),
                    "docker-compose.yml")
    print("Run `sudo docker-compose run --rm vuln bash` to start container")
    print("Don't forget to use tmux!")


@cli.command()
@click.option('--elf', '-e', default='', help='Binary to patch')
def detime(elf: str):
    e = ELF(elf)
    patch(e)
    print("Patched!")


@cli.command()
@click.argument("elf")
def menu(elf: str):
    e = ELF(elf)
    mg.menu_gen(e)


@cli.command()
@click.option('--url', '-u', default='', help='web url')
@click.option('--name', '-n', default='solve', help='web url')
def web(url: str, name: str):
    web_tg.generate_template(url, name)


@cli.command()
def wasabi():
    init_wasabi()


if __name__ == '__main__':
    cli(obj={})
