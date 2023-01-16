import click
from dataset_utils import process, runcmd, db_construct, db_construct_slow
import random
import os

@click.command()
@click.option('--data', help='The folder contains the data')
@click.option('--s3',  help='The S3 bucket path for the dataset')
@click.option('--dest', help='The destination folder for the data, will be created and overwritten.')
@click.option('-g', is_flag=True, help='Generate dataset, you need also need to provide other specs')
@click.option('--dbfile', help='The database file')
@click.option('--slow', is_flag=True, help='Will significantly slow processing, but consume much less memory. Use it if you have less memory and good disk')
@click.option('-f', is_flag=True, help='Filter the data folder')
@click.option('--uppersize', help='Maximum size of binary file')
@click.option('--lowersize', help='Minimum size of binary file')
@click.option('--amount', help='Files to be processed')


def main(data, s3, dest, g, dbfile, slow):
    """Assemblage Dataset Interface"""
    if g:
        assert data
        assert dbfile
        runcmd(f"rm -rf {dbfile}")
        if slow:
            db_construct_slow(dbfile, data)
        else:
            db_construct(dbfile, data)
    if data:
        runcmd(f"rm -rf {dest}")
        process(data, dest)
    elif s3:
        runcmd(f"mkdir {dest}")
        runcmd(f"aws s3 cp s3://assemblage-data/data/ ./{dest} --recursive")
        process(dest)


if __name__ == '__main__':
    main()