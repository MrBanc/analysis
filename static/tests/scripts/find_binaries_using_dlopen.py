import subprocess
import os

for (root,dirs,files) in os.walk('/bin/',topdown=True):
    for f in files:
        f_name = f"{root}{f}"

        output = subprocess.run(["file", f_name], capture_output=True)
        str_output = output.stdout.decode("utf8")
        if str_output.split()[1] != "ELF":
            continue

        output = subprocess.run(["objdump", "-d", "--disassembler-options=intel", f_name], capture_output=True)

        str_output = output.stdout.decode("utf8")
        if "<dlmopen@" in str_output:
            print(f"dlmopen {f_name}")
        if "<dlopen@" in str_output:
            print(f"dlopen {f_name}")
        if "<dlsym@" in str_output:
            print(f"dlsym {f_name}")
