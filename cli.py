import click
from dataset_utils import process, runcmd, db_construct, filter_size, update_license
import random
import os

@click.command()
@click.option('--data', help='The folder contains the data')
@click.option('--s3',  is_flag=True, help='The S3 bucket path for the dataset')
@click.option('--dest', help='The destination folder for the data, will be created and overwritten.')
@click.option('-g', is_flag=True, help='Generate dataset, you need also need to provide other specs')
@click.option('--dbfile', help='The database file')
# @click.option('--slow', is_flag=True, help='Will significantly slow processing, but consume much less memory. Use it if you have less memory and good disk')
@click.option('-f', is_flag=True, help='Filter the data folder')
@click.option('--uppersize', help='Maximum size of binary file')
@click.option('--lowersize', help='Minimum size of binary file')
@click.option('--amount', help='Files to be processed')
@click.option('--lines', is_flag=True, help='Store lines information in the database')
@click.option('--functions', is_flag=True, help='Store lines information in the database')
@click.option('--rvas', is_flag=True, help='Store RVA information in the database')
@click.option('--pdbs', is_flag=True, help='Store PDB file, takes up additional space')
@click.option('--inplace', is_flag=True, help='Delete zip file while processing')
@click.option('--license', is_flag=True, help='Update license information in database')



def main(data, s3, dest, g, dbfile, f, uppersize, lowersize, amount, lines, functions, rvas, pdbs, inplace, license):
    """Assemblage Dataset Interface"""
    if f:
        assert data
        assert dest
        assert uppersize
        assert lowersize
        filter_size(data, dest, uppersize, lowersize, amount)
    if g:
        assert data
        assert dbfile
        runcmd(f"rm -rf {dbfile}")
        db_construct(dbfile, data, lines, functions, rvas, pdbs)
    elif data:
        # runcmd(f"rm -rf {dest}")
        process(data, dest, inplace)
    elif s3:
        runcmd(f"mkdir {dest}")
        os.system(f"aws s3 cp s3://assemblage-data/platform/windows/ ./{dest} --recursive")
    elif license:
        assert dbfile
        update_license(dbfile)


if __name__ == '__main__':
    main()