import json
import subprocess


def accept_license():
    # Accept Azure Marketplace image terms so that the image can be used to create VMs
    subprocess.Popen(
        [
            "az",
            "vm",
            "image",
            "terms",
            "accept",
            "--urn",
            "aviatrix-systems:aviatrix-bundle-payg:aviatrix-enterprise-bundle-byol:latest",
        ],
        stdout=subprocess.PIPE,
    )


def get_license_details():
    # Get the details if Azure Marketplace image terms
    process = subprocess.Popen(
        [
            "az",
            "vm",
            "image",
            "terms",
            "show",
            "--urn",
            "aviatrix-systems:aviatrix-bundle-payg:aviatrix-enterprise-bundle-byol:latest",
        ],
        stdout=subprocess.PIPE,
    )
    out = process.communicate()[0]
    py_dict = json.loads(out)
    return py_dict


if __name__ == "__main__":
    details = get_license_details()
    if not details["accepted"]:
        accept_license()
