# %%
import os
import glob
import shutil
from tqdm.auto import tqdm


# %%
# for f in tqdm(glob.glob("assmlinux/**/*", recursive=1)):
#     if os.path.isfile(f) and not f.endswith(".zip"):
#         shutil.copy(f, os.path.join("assmlinux_flatten", os.urandom(4).hex()+os.path.basename(f)))

# %%
import subprocess
result = ""
fs = list(glob.glob("assmlinux/**/*", recursive=1))
fs.reverse()
for f in tqdm(fs):
    if f.endswith("zip") or os.path.isdir(f):
        continue
    try:
        result = subprocess.check_output([f"readelf --debug-dump=info {f}"], shell=True).decode()
        if "Compilation Unit" in result:
            basename = os.path.basename(f)
            idstring = os.urandom(4).hex()
            os.system(f"mv {f} assmlinux_debug/{idstring}-{basename}")
        else:
            os.system(f"rm {f}")
    except subprocess.CalledProcessError:
        os.system(f"rm {f}")


# %%



