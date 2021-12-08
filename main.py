import click
import ctflib.pwn.template_gen as tg


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


if __name__ == '__main__':
    cli(obj={})
