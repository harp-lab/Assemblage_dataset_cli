import os
import glob
import random
from tqdm.auto import tqdm
import json
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import math
import zipfile
import concurrent.futures
import shutil
import time
import re
import requests
import pefile

from db import Dataset_DB
from dataset_orm import *

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


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


TIMEOUT = 15
checksum_format = r"\s\((MD5|0x3).*\)"

def get_md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def get_sha256(bytes):
    shaobj = hashlib.sha256()
    shaobj.update(bytes)
    return shaobj.hexdigest()

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


def process(zip_path, dest, inplace):
    runcmd(f"rm -rf {dest}")
    runcmd(f"mkdir {dest}")
    print("Unzip files")
    zipped_files = glob.glob(f"{zip_path}/*.zip")
    threads = []
    for f in tqdm(zipped_files):
        threading.Thread(target=unzip_process, args=(f, dest, inplace)).start()


def unzip_process(f, dest, inplace):
    """Unzip the file and check if it is a valid zip file"""
    tmp = f"{dest}/{os.urandom(32).hex()}"
    with zipfile.ZipFile(f, 'r') as zip_ref:
        zip_ref.extractall(tmp)
    if os.path.isfile(os.path.join(tmp, "pdbinfo.json")):
        try:
            with open(os.path.join(tmp, "pdbinfo.json")) as pdbf:
                pdb_info_dict = json.load(pdbf)
        except:
            return
        for Binary_info_list in pdb_info_dict["Binary_info_list"]:
            if len(Binary_info_list["functions"]) == 0:
                try:
                    shutil.rmtree(tmp)
                except:
                    pass
                return
        binfiles = glob.glob(tmp+"/**/*.exe", recursive=True)+glob.glob(tmp+"/**/*.dll", recursive=True)
        pdbfiles = glob.glob(tmp+"/**/*.pdb", recursive=True)
        if len(binfiles)==0:
            shutil.rmtree(tmp)
            return
        plat = pdb_info_dict["Platform"] or "unknown"
        mode = pdb_info_dict["Build_mode"]
        toolv = pdb_info_dict["Toolset_version"]
        opti = pdb_info_dict["Optimization"]
        github_url = pdb_info_dict["URL"]
        for binf in binfiles+pdbfiles:
            if "x86" in binf:
                plat = "x86"
            elif "x64" in binf:
                plat = "x64"
            identifier = f"{get_md5(github_url)[:5]}_{plat}_{mode}_{toolv}_{opti}"
            if not os.path.isdir(f"{dest}/{identifier}"):
                os.makedirs(f"{dest}/{identifier}")
            bin_name = os.path.basename(binf)
            bin_dest = f"{identifier}_{bin_name}"
            shutil.move(binf, f"{dest}/{identifier}/{bin_dest}")
            assert os.path.isfile(f"{dest}/{identifier}/{bin_dest}")
        pdbpath = os.path.join(tmp, "pdbinfo.json")
        shutil.move(pdbpath, f"{dest}/{identifier}/{identifier}.json")
        assert os.path.isfile(f"{dest}/{identifier}/{identifier}.json")
    # else:
    #     #Linux data doesn't have pdbinfo.json
    #     allfiles = glob.glob(tmp+"/**/*", recursive=True)
    #     binfiles = []
    #     identifier = f"{os.urandom(6).hex()}_linux"
    #     for f in allfiles:
    #         if is_elf_bin(f):
    #             binfiles.append(f)
    #     for binfile in binfiles:
    #         if not os.path.isdir(f"{dest}/{identifier}"):
    #             os.makedirs(f"{dest}/{identifier}")
    #         bin_name = os.path.basename(binfile)
    #         bin_dest = f"{identifier}_{bin_name}"
    #         shutil.move(binfile, f"{dest}/{identifier}/{bin_dest}")
    #         assert os.path.isfile(f"{dest}/{identifier}/{bin_dest}")
    #     with open(f"{dest}/{identifier}/{identifier}.json", 'w') as f:
    #         json.dump({"Platform": "Linux",
    #                    "Build_mode": "unknown",
    #                    "Toolset_version": "GCC",
    #                    "Optimization":"unknown",
    #                    "URL":"unknown"}, f)
    runcmd(f"rm -rf {tmp}")
    if inplace:
        runcmd(f"rm {f}")


def filter_size(size_upper, size_lower, file_limit, binpath, dest_path):
    binpath = os.path.join(binpath, "bins")
    print("Filtering files")
    if not file_limit:
        file_limit = math.inf
    if not size_lower:
        size_lower = 0
    if not size_upper:
        size_upper = math.inf
    for f in tqdm(os.listdir(binpath)):
        bts = os.path.getsize(os.path.join(binpath, f))
        kb = bts/1024
        if kb >= size_lower and kb <= size_upper:
            runcmd(
                f"cp {os.path.join(binpath, f)} {os.path.join(dest_path, f)}")
            file_limit -= 1
        if not file_limit:
            break
    print(f"Copying files")
    for f in tqdm(os.listdir(dest_path)):
        urlmd5 = f.split("_")[0]
        runcmd(f"cp {binpath.replace('/bins','')}/jsons/{urlmd5}* {dest_path}")
    print("Copying pdb files")
    for f in tqdm(os.listdir(dest_path)):
        if f.endswith("json"):
            with open(os.path.join(dest_path, f)) as fhandler:
                pdb = json.load(fhandler)
            plat = pdb["Platform"]
            mode = pdb["Build_mode"]
            toolv = pdb["Toolset_version"]
            md5 = get_md5(pdb["URL"])
            opti = pdb["Optimization"]
            bin_prefix = f"{md5}_{plat}_{mode}_{toolv}_{opti}"
            try:
                os.makedirs(os.path.join(dest_path, bin_prefix))
            except:
                pass
            for x in os.listdir(dest_path):
                if x.startswith(bin_prefix) and (x.endswith("exe") or x.endswith("dll")):
                    runcmd(
                        f"mv {dest_path}/{x} {os.path.join(dest_path, bin_prefix)}/{x}")
            runcmd(f"mv {dest_path}/{f} {os.path.join(dest_path, bin_prefix)}")
    for folder in os.listdir(dest_path):
        if os.path.isdir(f"{dest_path}/{folder}"):
            files = os.listdir(f"{dest_path}/{folder}")
            if len(files) < 2:
                runcmd(f"rm -r {dest_path}/{folder}")
        else:
            runcmd(f"rm -r {dest_path}/{folder}")


def db_construct(dbfile, target_dir, include_lines, include_functions, include_rvas, include_pdbs):
    print("Creating database")
    try:
        os.remove(dbfile)
    except:
        pass
    init_clean_database(f"sqlite:///{dbfile}")
    db = Dataset_DB(f"sqlite:///{dbfile}")
    print("Writing data to database")
    binary_id = 100
    function_id = 1
    binary_ds = {}
    function_ds = []
    line_ds = []
    rva_ds = []
    pdb_ds = []
    for identifier in tqdm(os.listdir(target_dir)):
        if not os.path.isfile(os.path.join(target_dir, identifier, f"{identifier}.json")):
            runcmd(f"rm -r {target_dir}/{identifier}")
            continue
        bins = [x for x in os.listdir(os.path.join(target_dir, identifier)) if (x.lower().endswith(".exe") or x.lower().endswith(".dll"))]
        pdbs = [x for x in os.listdir(os.path.join(target_dir, identifier)) if x.lower().endswith(".pdb")]
        pdbinfo = json.load(
            open(os.path.join(target_dir, identifier, f"{identifier}.json")))
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
            filename = binfile.replace(identifier+"_", "")
            path = assign_path(str(binary_id))
            if not os.path.isdir(os.path.join(target_dir, path)):
                os.makedirs(os.path.join(target_dir, path))
            while os.path.isfile(os.path.join(target_dir, path, filename)):
                binary_id+=1
                path = assign_path(str(binary_id))
            shutil.move(os.path.join(target_dir, identifier, binfile),
                        os.path.join(target_dir, path, filename))
            assert os.path.isfile(os.path.join(target_dir, path, filename))
            try:
                pushed_at = int(time.mktime(datetime.datetime.strptime(pdbinfo["Pushed_at"], '%m/%d/%Y, %H:%M:').timetuple()))
            except:
                pushed_at = 0
            binary_ds[binary_id] = {
                "id": binary_id,
                "github_url": pdbinfo["URL"],
                "file_name": filename,
                "platform": pdbinfo["Platform"],
                "build_mode": pdbinfo["Build_mode"],
                "toolset_version": pdbinfo["Toolset_version"],
                "pushed_at": pushed_at,
                "optimization": pdbinfo["Optimization"],
                "path": os.path.join(path, filename),
                "size": os.path.getsize(os.path.join(target_dir, path, filename))//1024
            }
            pdb_ds.extend([{
                "binary_id": binary_id,
                "pdb_path": x} 
                    for x in pdb_paths_moved])
            binary_rela[filename] = binary_id
            binary_id += 1
            for binary_file in pdbinfo["Binary_info_list"]:
                if filename == binary_file["file"].replace("\\", "/").split("/")[-1]:
                    bin_id = binary_rela[filename]
                    if len(binary_file["functions"]) == 0:
                        del binary_ds[bin_id]
                        continue
                    for function_info in binary_file["functions"]:
                        function_name = function_info["function_name"]
                        intersect_ratio = max(float((function_info["intersect_ratio"].replace("%", "")))/100, 0)
                        source_file = re.sub(checksum_format, "", function_info["source_file"])
                        rva_ds.extend([{
                            "start": int(x['rva_start'], 16),
                            "end": int(x['rva_end'], 16),
                            "function_id": function_id,
                        } for x in function_info["function_info"]])

                        function_ds.append({
                            "name": function_name,
                            "intersect_ratio": intersect_ratio,
                            "binary_id": bin_id,
                            "id": function_id
                        })
                        binary_ds[bin_id]["source_file"] = source_file
                        for line_info in function_info["lines"]:
                            line_number = line_info["line_number"]
                            length = line_info["length"]
                            source_code = line_info["source_code"]
                            if "source_file" in line_info:
                                source_file = re.sub(checksum_format, "", line_info["source_file"])
                            line_ds.append({
                                "line_number": line_number,
                                "length": length,
                                "source_code": source_code,
                                "function_id": function_id})
                        function_id += 1
        runcmd(f"rm -rf {target_dir}/{identifier}")
        if len(binary_ds) > 10000:
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
    print(
        f"Finished, database location: {dbfile}, binary location: {target_dir}")
    db.shutdown()

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

def update_hash(dbfile, dataset_path):
    print("Adding hash to each functions")
    db = Dataset_DB(f"sqlite:///{dbfile}")
    for bin_obj in tqdm(db.get_all_bins()):
    # for bin_obj in [Binary(id=100, file_name="PaintDLL.dll")]:
        bindir = assign_path(bin_obj.id)
        binpath = os.path.join(dataset_path, bindir, bin_obj.file_name)
        pe_obj = pefile.PE(binpath, fast_load=1)
        mapped_memory = pe_obj.get_memory_mapped_image()
        if not os.path.isfile(binpath):
            print("Error file not existing", binpath)
        for func in db.get_func_by_binid(bin_obj.id):
            if func.hash!="":
                continue
            func_bytes = []
            for rva_block in db.get_rva_by_funcid(func.id):
                start_rva = rva_block.start
                end_rva = rva_block.end
                func_bytes.append(mapped_memory[start_rva:end_rva])
            sha256 = get_sha256(b"".join(func_bytes))
            db.update_func_hash(func.id, sha256)
    db.shutdown()
