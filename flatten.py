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
for f in tqdm(glob.glob("assmlinux_flatten/**/*", recursive=1)):
    try:
        result = subprocess.check_output([f"readelf --debug-dump=info {f}"], shell=True).decode()
        # print(result)
        assert ("Compilation Unit" in result)
    except:
        print(f, result)
        os.system(f'rm {f}')


# %%



