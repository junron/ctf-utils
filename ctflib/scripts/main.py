import click
import ctflib.pwn.template_gen as tg
import ctflib.web.template_gen as web_tg
from ctflib.web.wasabi import init_wasabi


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
@click.option('--url', '-u', default='', help='web url')
@click.option('--name', '-n', default='solve', help='web url')
def web(url: str, name: str):
    web_tg.generate_template(url, name)


@cli.command()
def wasabi():
    init_wasabi()
    
if __name__ == '__main__':
    cli(obj={})
