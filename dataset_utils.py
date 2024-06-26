import os
import glob
import random
from tqdm.auto import tqdm
import json
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
import hashlib
import threading
import math
import zipfile
import shutil
import time
import re
import requests
import pefile
import logging
import sqlite3
import json
import pefile

from db import Dataset_DB
from dataset_orm import *
from multiprocessing import Pool
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

METAFILE = "assemblage_meta.json"

logging.basicConfig(format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.INFO)

def is_elf_bin(location):
    if not os.path.isfile(location):
        return False
    with open(location, 'rb') as f:
        try:
            ef = ELFFile(f)
            if ef.header['e_type'] == 'ET_EXEC' or ef.header['e_type'] == 'ET_DYN':
                return True
        except ELFError:
            return False

def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()

TIMEOUT = 15
checksum_format = r"\s\((MD5|0x3).*\)"

def get_md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def assign_path(s):
    s = str(s)[::-1]
    path_layers = re.findall('.{2}', str(s))
    return os.path.join(*path_layers)

def runcmd(cmd):
    stdout, stderr = None, None
    if os.name != 'nt':
        cmd = "exec " + cmd
    with Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=TIMEOUT)
        except TimeoutExpired:
            if os.name == 'nt':
                Popen("TASKKILL /F /PID {pid} /T".format(pid=process.pid))
            else:
                process.kill()
                exit()
    return stdout, stderr, process.returncode


def process(zip_path, dest, inplace, nopdb):
    print("Checking all files")
    zipped_files = glob.glob(f"{zip_path}/**/*.zip", recursive=1)
    print(len(zipped_files), 'found')
    pool = Pool(128)
    for f in zipped_files:
        pool.apply_async(unzip_process, args=(f, dest, inplace, nopdb,))
    pool.close()
    pool.join()

def unzip_process(zipfile_path, dest, inplace, nopdb):
    """Unzip the file and check if it is a valid zip file"""
    tmp = f"{dest}/{os.urandom(32).hex()}"
    try:
        with zipfile.ZipFile(zipfile_path, 'r') as zip_ref:
            zip_ref.extractall(tmp)
    except Exception as e:
        print(e)
        return
    if len(os.listdir(tmp)) == 1:
        tmp = os.path.join(tmp, os.listdir(tmp)[0])
    if os.path.isfile(os.path.join(tmp, METAFILE)):
        with open(os.path.join(tmp, METAFILE)) as pdbf:
            pdb_info_dict = json.load(pdbf)
        binfiles = glob.glob(tmp+"/**/*.exe", recursive=True)+glob.glob(tmp+"/**/*.dll", recursive=True)+glob.glob(tmp+"/**/*.EXE", recursive=True)+glob.glob(tmp+"/**/*.DLL", recursive=True)
        for f in glob.glob(tmp+"/**/*", recursive=True):
            if is_elf_bin(f):
                binfiles.append(f)
        pdbfiles = glob.glob(tmp+"/**/*.pdb", recursive=True)
        if nopdb:
            pdbfiles = []
        if len(binfiles)==0:
            shutil.rmtree(tmp)
            return
        plat = pdb_info_dict["Platform"] if "Platform" in pdb_info_dict else ""
        mode = pdb_info_dict["Build_mode"]
        toolv = pdb_info_dict["Toolset_version"] if "Toolset_version" in pdb_info_dict else "?"
        pdb_info_dict["Toolset_version"] = toolv
        opti = pdb_info_dict["Optimization"]
        github_url = pdb_info_dict["URL"]
        for binf in binfiles+pdbfiles:
            identifier = f"{get_md5(github_url)}_{plat}_{mode}_{toolv}_{opti}"
            if not os.path.isdir(f"{dest}/{identifier}"):
                os.makedirs(f"{dest}/{identifier}")
            bin_name = os.path.basename(binf)
            bin_dest = f"{identifier}_{bin_name}"
            shutil.move(binf, f"{dest}/{identifier}/{bin_dest}")
            assert os.path.isfile(f"{dest}/{identifier}/{bin_dest}")
        shutil.move(os.path.join(tmp, METAFILE), f"{dest}/{identifier}/{METAFILE}")
        assert os.path.isfile(f"{dest}/{identifier}/{METAFILE}")
    if len(os.listdir(os.path.join(dest, identifier))) < 2:
        runcmd(f"rm -rf {dest}/{identifier}")
    runcmd(f"rm -rf {tmp}")
    print("Inflated", zipfile_path, " -> ", os.listdir(f"{dest}/{identifier}"))
    return


# Actual function to construct the database
def db_construct(dbfile, target_dir, include_lines, include_functions, include_rvas, include_pdbs):
    logging.info("Creating database")
    if os.path.isfile(dbfile):
        connection = sqlite3.connect(dbfile)
        cursor = connection.cursor()
        ids = cursor.execute('SELECT id FROM binaries')
        binary_id = max([x[0] for x in ids]+[1000]) + 1
        ids = cursor.execute('SELECT id FROM functions')
        function_id = max([x[0] for x in ids]+[1000]) + 1
    else:
        init_clean_database(f"sqlite:///{dbfile}")
        binary_id = 1000
        function_id = 1
    db = Dataset_DB(f"sqlite:///{dbfile}")
    logging.info("Sorting files")
    binary_ds = {}
    function_ds = []
    line_ds = []
    rva_ds = []
    pdb_ds = []
    target_folders = os.listdir(target_dir)
    for identifier in tqdm(target_folders):
        if len(identifier) == 2:
            print("Processed, skip")
            continue
        if not os.path.isfile(os.path.join(target_dir, identifier, METAFILE)):
            # print("Missing meta data, skip", os.path.join(target_dir, identifier, METAFILE))
            # print("Missing meta data, ", os.listdir(os.path.join(target_dir, identifier)))
            runcmd(f"rm -r {target_dir}/{identifier}")
            continue
        bins = [x for x in os.listdir(os.path.join(target_dir, identifier)) if (x.lower().endswith(".exe")\
                                                                         or x.lower().endswith(".dll")\
                                                                         or is_elf_bin(os.path.join(target_dir, identifier, x)))]
        pdbs = [x for x in os.listdir(os.path.join(target_dir, identifier)) if x.lower().endswith(".pdb")]
        try:
            pdbinfo = json.load(
                open(os.path.join(target_dir, identifier, METAFILE)))
        except:
            print("Missing meta data, skip", os.path.join(target_dir, identifier, METAFILE))
            runcmd(f"rm -r {target_dir}/{identifier}")
            continue
        binary_rela = {}
        pdb_paths_moved = []
        if include_pdbs:
            for pdbfile in pdbs:
                pdb_folder = assign_path(str(binary_id))
                if not os.path.isdir(os.path.join(target_dir, pdb_folder)):
                    os.makedirs(os.path.join(target_dir, pdb_folder))
                shutil.move(os.path.join(target_dir, identifier, pdbfile),
                    os.path.join(target_dir, pdb_folder, pdbfile))
                pdb_paths_moved.append(os.path.join(pdb_folder, pdbfile))
        for binfile in bins:
            binary_id += 1
            filename = binfile.replace(identifier+"_", "")
            path = assign_path(str(binary_id))
            if not os.path.isdir(os.path.join(target_dir, path)):
                if os.path.isfile(os.path.join(target_dir, path)):
                    os.remove(os.path.join(target_dir, path))
                    db.delete_binary("?", path)
                os.makedirs(os.path.join(target_dir, path))
            old_id = binary_id
            for binary_id in range(old_id, old_id+10000):
                path = assign_path(str(binary_id))
                if not os.path.isfile(os.path.join(target_dir, path, filename)):
                    break
            try:
                shutil.move(os.path.join(target_dir, identifier, binfile),
                    os.path.join(target_dir, path, filename))
            except:
                print(f"Error moving {os.path.join(target_dir, identifier, binfile)} to {os.path.join(target_dir, path, filename)}")
                continue
            assert os.path.isfile(os.path.join(target_dir, path, filename))
            if "Pushed_at" in pdbinfo:
                try:
                    pushed_at = int(time.mktime(datetime.datetime.strptime(pdbinfo["Pushed_at"], '%m/%d/%Y, %H:%M:%S').timetuple()))
                except:
                    pushed_at = 0
            else:
                try:
                    pushed_at = int(time.mktime(datetime.datetime.strptime(pdbinfo["updated_at"], '%m/%d/%Y, %H:%M:%S').timetuple()))
                except:
                    pushed_at = 0
            assert binary_id not in binary_ds
            binary_ds[binary_id] = {
                "id": binary_id,
                "github_url": pdbinfo["URL"] if "URL" in pdbinfo else pdbinfo["url"],
                "file_name": filename,
                "platform": pdbinfo["Platform"] if "Platform" in pdbinfo else "",
                "build_mode": pdbinfo["Build_mode"] if "Build_mode" in pdbinfo else "",
                "toolset_version": pdbinfo["Toolset_version"] if "Toolset_version" in pdbinfo else "",
                "repo_last_update": pushed_at,
                "repo_commit_hash": pdbinfo["Commit"],
                "optimization": pdbinfo["Optimization"] if "Optimization" in pdbinfo else pdbinfo["flags"],
                "path": os.path.join(path, filename),
                "size": os.path.getsize(os.path.join(target_dir, path, filename))//1024,
                "hash": sha256sum(os.path.join(target_dir, path, filename))
            }
            pdb_ds.extend([{
                "binary_id": binary_id,
                "pdb_path": x} 
                    for x in pdb_paths_moved])
            binary_rela[filename] = binary_id
            if "Binary_info_list" in pdbinfo:
                for binary_file in pdbinfo["Binary_info_list"]:
                    mapped_memory = ""
                    try:
                        pe_obj = pefile.PE(os.path.join(target_dir, path, filename), fast_load=1)
                        mapped_memory = pe_obj.get_memory_mapped_image()
                    except:
                        print("Can't retrive PE image, skip")
                        continue
                    if filename in binary_file["file"]:
                        bin_id = binary_rela[filename]
                        for function_info in binary_file["functions"]:
                            function_name = function_info["function_name"]
                            rvablocks = [{
                                            "start": int(x['rva_start'], 16),
                                            "end": int(x['rva_end'], 16),
                                            "function_id": function_id,
                                        } for x in function_info["function_info"]]
                            for rvablock in rvablocks:
                                rva_ds.append(rvablock)
                            function_obj = {
                                "name": function_name,
                                "binary_id": bin_id,
                                "id": function_id,
                                "hash": get_hash_bin_rva(mapped_memory, 
                                        [[x["start"], x["end"]] for x in rvablocks]),
                                # "body_comments":"",
                                "top_comments":"",
                                "source_codes":"",
                                # "source_codes_ctags":"",
                                "prototype":"",
                                "source_file":""}
                            if "source_codes" in function_info:
                                function_obj["source_codes"] = function_info["source_codes"]
                            # if "source_codes" in function_info:
                            #     function_obj["source_codes"] = function_info["source_codes"]
                            # if "source_codes_ctags" in function_info:
                            #     function_obj["source_codes_ctags"] = function_info["source_codes_ctags"]
                            if "top_comments" in function_info:
                                function_obj["top_comments"] = (function_info["top_comments"])
                            # if "body_comments" in function_info:
                            #     function_obj["body_comments"] = (function_info["body_comments"])
                            if "prototype" in function_info:
                                function_obj["prototype"] = function_info["prototype"]
                            if "source_file" in function_info:
                                function_obj["source_file"] = function_info["source_file"]
                            function_ds.append(function_obj)
                            if include_lines:
                                for line_info in function_info["lines"]:
                                    line_number = line_info["line_number"]
                                    length = line_info["length"]
                                    source_code = line_info["source_code"]
                                    rva = line_info["rva"]
                                    if "source_file" in line_info:
                                        source_file = line_info["source_file"]
                                    if source_code:
                                        line_ds.append({
                                            "line_number": line_number,
                                            "source_file": source_file,
                                            "source_code": source_code,
                                            "function_id": function_id,
                                            "rva": "0x"+rva,
                                            "length": length})
                            function_id += 1

        runcmd(f"rm -rf {target_dir}/{identifier}")
        # Flush database
        # print(len(binary_ds), "binaries in memory")
        if len(binary_ds) > 2500:
            print("Flush database")
            db.bulk_add_binaries(binary_ds.values())
            if include_functions:
                db.bulk_add_functions(function_ds)
            if include_lines:
                db.bulk_add_lines(line_ds)
            if include_rvas:
                db.bulk_add_rvas(rva_ds)
            if include_pdbs:
                db.bulk_add_pdbs(pdb_ds)
            binary_ds = {}
            function_ds = []
            line_ds = []
            rva_ds = []
    db.bulk_add_binaries(binary_ds.values())
    if include_functions:
        db.bulk_add_functions(function_ds)
    if include_lines:
        db.bulk_add_lines(line_ds)
    if include_rvas:
        db.bulk_add_rvas(rva_ds)
    if include_pdbs:
        db.bulk_add_pdbs(pdb_ds)
    db.shutdown()

    print("Checking files")
    connection = sqlite3.connect(dbfile)
    cursor = connection.cursor()
    full_paths = {}
    paths = cursor.execute('SELECT path FROM binaries')
    for path in tqdm(paths):
        full_path = os.path.join(target_dir, path[0])
        assert os.path.isfile(full_path)
        full_paths[full_path] = 1
    files = [x for x in glob.glob(f'{target_dir}/**/*', recursive=True)]
    for x in tqdm(files):
        if os.path.isfile(x) and (not x.lower().endswith("pdb")) and x not in full_paths:
            os.remove(x)
    print(f"Finished database location: {dbfile}, binary location: {target_dir}")



def update_license(dbfile):
    db = Dataset_DB(f"sqlite:///{dbfile}")
    urls = db.get_all_urls()
    print("You can put tokens in a file called tokens.txt")
    if os.path.isfile("tokens.txt"):
        print("Using tokens.txt")
        with open("tokens.txt", "r") as f:
            tokens = [x.strip() for x in f.readlines()]
    else:
        tokens = [""]
    print(tokens)
    for url in tqdm(urls):
        username = url.split("/")[3]
        repository_name = url.split("/")[4]
        api_url = f"https://api.github.com/repos/{username}/{repository_name}"
        r = requests.get(api_url, auth=("", random.choice(tokens).strip()))
        license = ""
        if r.status_code == 200:
            if r.json()["license"]:
                license = r.json()["license"]["key"]
            else:
                license = "null"
        elif "Not Found" in r.text:
            license = "Not Found"
        elif "API rate limit" in r.text:
            time.sleep(10)
        print(url, license)
        db.update_license(url, license)
    db.shutdown()

def get_hash_bin_rva(mapped_memory, rvablocks):
    func_bytes = []
    shaobj = hashlib.sha256()
    rvablocks.sort(key=lambda x:x[0])
    for rva_block in rvablocks:
        start_rva = rva_block[0]
        end_rva = rva_block[1]
        try:
            shaobj.update(mapped_memory[start_rva:end_rva])
        except:
            return "null"
    return shaobj.hexdigest()
