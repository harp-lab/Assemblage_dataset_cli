import os
import glob
import random
import string
from tqdm import tqdm
import json
import random
import string
import hashlib
import json
import os
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import math
import zipfile
import concurrent.futures
import shutil
import logging

from db import Dataset_DB
from dataset_orm import *

TIMEOUT = 15

def get_md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def assign_path(filename):
    md5 = str(get_md5(filename)).upper()
    return f"{md5[:2]}/{md5[2:]}"

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


def process(zip_path, dest):
    runcmd(f"rm -rf {dest}")
    runcmd(f"mkdir {dest}")
    print("Sorting files")
    zipped_files = [x for x in glob.glob(f"{zip_path}/*") if os.path.isfile(x)]
    total = len(zipped_files)
    print(f"Found {total} zips")
    for f in tqdm(zipped_files):
        threading.Thread(target=unzip_process, args=(f, dest)).start()

def unzip_process(f, dest):
    tmp = f"{dest}/{os.urandom(32).hex()}"
    try:
        with zipfile.ZipFile(f, 'r') as zip_ref:
            zip_ref.extractall(tmp)
        if os.path.isfile(os.path.join(tmp, "pdbinfo.json")):
            with open(os.path.join(tmp, "pdbinfo.json")) as pdbf:
                pdb = json.load(pdbf)
            for Binary_info_list in pdb["Binary_info_list"]:
                if len(Binary_info_list["functions"]) == 0:
                    try:
                        shutil.rmtree(tmp)
                    except:
                        pass
                    return
            if glob.glob(tmp+"/*.exe")+glob.glob(tmp+"/*.dll") == []:
                return
            for binf in glob.glob(tmp+"/*.exe")+glob.glob(tmp+"/*.dll"):
                bin_name = binf.split("/")[-1]
                plat = pdb["Platform"] or "unknown"
                mode = pdb["Build_mode"]
                toolv = pdb["Toolset_version"]
                opti = pdb["Optimization"]
                github_url = pdb["URL"]
                identifier = get_md5(github_url)+f"_{plat}_{mode}_{toolv}_{opti}"
                bin_dest = f"{identifier}_{bin_name}"
                if not os.path.isdir(f"{dest}/{identifier}"):
                    os.makedirs(f"{dest}/{identifier}")
                else:
                    pass
                if not os.path.isfile(bin_dest):
                    shutil.move(binf, f"{dest}/{identifier}/{bin_dest}")
            pdbpath = os.path.join(tmp, "pdbinfo.json")
            shutil.move(pdbpath, f"{dest}/{identifier}/{identifier}.json")
        shutil.rmtree(tmp)
    except:
        pass
    try:
        shutil.rmtree(tmp)
    except:
        pass


def filter_size(size_upper, size_lower, file_limit, binpath, dest_path):
    binpath = binpath+"/bins"
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
        if kb>=size_lower and kb<=size_upper:
            runcmd(f"cp {os.path.join(binpath, f)} {os.path.join(dest_path, f)}")
            file_limit-=1
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
                    runcmd(f"mv {dest_path}/{x} {os.path.join(dest_path, bin_prefix)}/{x}")
            runcmd(f"mv {dest_path}/{f} {os.path.join(dest_path, bin_prefix)}")
    for folder in os.listdir(dest_path):
        if os.path.isdir(f"{dest_path}/{folder}"):
            files = os.listdir(f"{dest_path}/{folder}")
            if len(files)<2:
                runcmd(f"rm -r {dest_path}/{folder}")
        else:
            runcmd(f"rm {dest_path}/{folder}")

def db_construct(dbfile, target_dir, nolines):
    print("Creating database")
    try:
        os.remove(dbfile)
    except:
        pass
    init_clean_database(f"sqlite:///{dbfile}")
    db = Dataset_DB(f"sqlite:///{dbfile}")
    print("Preparing data")
    binary_id = 1
    function_id = 1
    binary_ds = {}
    function_ds = []
    line_ds = []
    for identifier in tqdm(os.listdir(target_dir)):
        if not os.path.isfile(os.path.join(target_dir, identifier, f"{identifier}.json")):
            continue
        bins = [x for x in os.listdir(os.path.join(target_dir, identifier)) if not x.endswith(".json")]
        pdbinfo = json.load(open(os.path.join(target_dir, identifier, f"{identifier}.json")))
        binary_rela = {}
        for binfile in bins:
            filename = binfile.replace(identifier+"_", "")
            path = f"{assign_path(binfile)}"
            path = "".join([x for x in path if (x in string.printable and x)])
            try:
                os.makedirs(f"{target_dir}/{path}")
            except:
                pass
            file_name_clean = "".join([x for x in binfile if (x in string.printable and x)])
            shutil.copy(os.path.join(target_dir, identifier, binfile), os.path.join(target_dir, path, file_name_clean))
            if not os.path.isfile(os.path.join(target_dir, path, file_name_clean)):
                continue
            binary_ds[binary_id] = {
                "id":binary_id,
                "github_url":pdbinfo["URL"],
                "path":os.path.join(target_dir, path, file_name_clean),
                "file_name":filename,
                "platform":pdbinfo["Platform"],
                "build_mode":pdbinfo["Build_mode"],
                "toolset_version":pdbinfo["Toolset_version"],
                "pushed_at":datetime.datetime.strptime(pdbinfo["Pushed_at"], '%m/%d/%Y, %H:%M:%S'),
                "optimization":pdbinfo["Optimization"],
                "size":os.path.getsize(os.path.join(target_dir, path, file_name_clean))//1024
            }
            binary_rela[filename] = binary_id
            binary_id+=1
            for binary_file in pdbinfo["Binary_info_list"]:
                if filename == binary_file["file"].replace("\\", "/").split("/")[-1]:
                    bin_id = binary_rela[filename]
                    if len(binary_file["functions"])==0:
                        del binary_ds[bin_id]
                        continue
                    for function_info in binary_file["functions"]:
                        function_name = function_info["function_name"]
                        intersect_ratio = float(function_info["intersect_ratio"].replace("%", ""))/100
                        source_file = function_info["source_file"]
                        rva_strings = ",".join([f"{x['rva_start']}-{x['rva_end']}" for x in function_info["function_info"]])
                        function_ds.append({
                            "name":function_name,
                            "source_file":source_file,
                            "intersect_ratio":intersect_ratio,
                            "rvas":rva_strings,
                            "binary_id":bin_id,
                            "id":function_id
                        })
                        source_file = ""
                        for line_info in function_info["lines"]:
                            line_number = line_info["line_number"]
                            rva_addr = line_info["rva"]
                            length = line_info["length"]
                            source_code = line_info["source_code"]
                            if "source_file" in line_info:
                                source_file = line_info["source_file"]
                            line_ds.append({
                                "line_number":line_number,
                                "rva":rva_addr,
                                "length":length,
                                "source_code":source_code,
                                "function_id":function_id})
                        function_id+=1
        runcmd(f"rm -rf {target_dir}/{identifier}")
        if len(binary_ds)>1000:
            db.bulk_add_binaries(binary_ds.values())
            db.bulk_add_functions(function_ds)
            db.bulk_add_lines(line_ds)
            binary_ds = {}
            function_ds = []
            line_ds = []
    db.bulk_add_binaries(binary_ds.values())
    db.bulk_add_functions(function_ds)
    if nolines:
        db.bulk_add_lines(line_ds)
    print(f"Finished, database location: {dbfile}, binary location: {target_dir}")

def db_construct_slow(dbfile, target_dir, nolines):
    print("Creating database")
    try:
        os.remove(dbfile)
    except:
        pass
    init_clean_database(f"sqlite:///{dbfile}")
    db = Dataset_DB(f"sqlite:///{dbfile}")
    print("Constructing database, this will long time")

    for folder in tqdm(os.listdir(target_dir)):
        identifier = folder
        bins = [x for x in os.listdir(os.path.join(target_dir, folder)) if not x.endswith(".json")]
        pdbinfo = json.load(open(os.path.join(target_dir, identifier, f"{identifier}.json")))
        binary_rela = {}
        for binfile in bins:
            filename = binfile.replace(identifier+"_", "")
            path = f"{assign_path(binfile)}"
            path = "".join([x for x in path if (x in string.printable and x)])
            try:
                os.makedirs(f"{target_dir}/{path}")
            except:
                pass
            file_name_clean = "".join([x for x in binfile if (x in string.printable and x)])
            runcmd(f"mv {target_dir}/{folder}/{binfile} {target_dir}/{path}/{file_name_clean}")
            bin_id = db.add_binary(github_url=pdbinfo["URL"],
                        path=os.path.join(target_dir, path, file_name_clean),
                        file_name=filename,
                        platform=pdbinfo["Platform"],
                        build_mode=pdbinfo["Build_mode"],
                        toolset_version=pdbinfo["Toolset_version"],
                        pushed_at=datetime.datetime.strptime(pdbinfo["Pushed_at"], '%m/%d/%Y, %H:%M:%S'),
                        optimization=pdbinfo["Optimization"],
                        size=os.path.getsize(os.path.join(target_dir, path, file_name_clean))//1024
                        )
            binary_rela[filename] = bin_id
            for binary_file in pdbinfo["Binary_info_list"]:
                if filename == binary_file["file"].replace("\\", "/").split("/")[-1]:
                    bin_id = binary_rela[filename]
                    if len(binary_file["functions"])==0:
                        db.delete_binary(bin_id)
                    for function_info in binary_file["functions"]:
                        function_name = function_info["function_name"]
                        intersect_ratio = float(function_info["intersect_ratio"].replace("%", ""))/100
                        source_file = function_info["source_file"]
                        rva_strings = ",".join([f"{x['rva_start']}-{x['rva_end']}" for x in function_info["function_info"]])
                        function_id = db.add_function(name=function_name,
                                        source_file=source_file,
                                        intersect_ratio=intersect_ratio,
                                        rvas=rva_strings,
                                        binary_id=bin_id)
                        source_file = ""
                        for line_info in function_info["lines"]:
                            line_number = line_info["line_number"]
                            rva_addr = line_info["rva"]
                            length = line_info["length"]
                            source_code = line_info["source_code"]
                            if "source_file" in line_info:
                                source_file = line_info["source_file"]
                            db.add_line(line_number=line_number,
                                        rva=rva_addr,
                                        length=length,
                                        source_code=source_code,
                                        function_id=function_id)
        os.remove(os.path.join(target_dir, identifier, f"{identifier}.json"))
        runcmd(f"rm -rf {target_dir}/{folder}")
    print(f"Finished, database location: {dbfile}, binary location: {target_dir}")