import json
import subprocess
import pdb
import sys


def get_vm_name(rg,scaleset):
    # Get the details if Azure Marketplace image terms
    process = subprocess.Popen(
        [
            "az",
            "vmss",
            "list-instances",
            "--resource-group",
            rg,
            "--name",
            scaleset,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    out = process.communicate()[0]
    pdb.set_trace()
    py_dict = json.loads(out)
    return py_dict[0]['name']

def private_ip(name):
    # Get the details if Azure Marketplace image terms
    process = subprocess.Popen(
        [
            "az",
            "vm",
            "list-ip-addresses",
            "--name",
            name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    out = process.communicate()[0]
    py_dict = json.loads(out)
    return py_dict[0]['virtualMachine']['network']['privateIpAddresses'][0]

if __name__ == "__main__":
    rg = sys.argv[1]
    scaleset = sys.argv[2]
    vm_name = get_vm_name(rg, scaleset)
    ip = private_ip(vm_name)
    print(ip)