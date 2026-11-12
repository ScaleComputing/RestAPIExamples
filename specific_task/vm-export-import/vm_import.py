#!/usr/bin/env python3
"""
vm_import.py

Import a VM into an SC//HyperCore(TM) cluster from a previously exported
directory on an SMB share, using POST /rest/v1/VirDomain/import.

The source directory is one produced by vm_export.py (or by the cluster UI's
export): a definition file plus one qcow2 per disk.

Usage
    ./vm_import.py --node 10.0.0.1 --name my-vm-restored \
        --smb-server 10.0.0.50 --smb-share exports --smb-path hcexports/my-vm \
        --smb-user administrator --smb-password 'secret'

    # complete pathURI instead of the --smb-* options
    ./vm_import.py --node 10.0.0.1 --name my-vm-restored \
        --path-uri 'smb://administrator:secret@10.0.0.50/exports/hcexports/my-vm' \
        --definition-file my-vm.xml

    # seed the imported VM with cloud-init user-data / meta-data
    ./vm_import.py ... --user-data-file user-data.yaml --meta-data-file meta-data.yaml

Two things to know about the result:

  * the imported VM is created stopped
  * its device list does not match the source -- an import attaches an empty
    IDE_CDROM, and for a Windows `operatingSystem` it also attaches
    scale-guest-tools.iso. Check blockDevs before starting the VM.

`tags`, `description`, `mem`, `numVCPU` and `machineType` did come across
unchanged on a 9.7.8 cluster.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""

import argparse
import base64
import getpass
import os
import sys

from hypercore_transfer import (
    ApiError,
    TaskFailed,
    api_base,
    build_smb_uri,
    make_session,
    mask_uri,
    post_and_wait,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Import a VM into an SC//HyperCore cluster from an SMB share.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--node", required=True, help="cluster node IP or FQDN")
    parser.add_argument("--username", help="cluster user (default $SC_USERNAME)")
    parser.add_argument("--password", help="cluster password (default $SC_PASSWORD, else prompt)")
    parser.add_argument("--api-version", default="v1", choices=("v1", "v2"),
                        help="REST API version; an http:// pathURI needs v2")

    parser.add_argument("--name", help="name for the imported VM "
                                       "(default: the name recorded in the definition file)")

    source = parser.add_argument_group("import source (use --path-uri OR the --smb-* options)")
    source.add_argument("--path-uri", help="complete pathURI, credentials included")
    source.add_argument("--smb-server", help="SMB server IP or hostname")
    source.add_argument("--smb-share", help="SMB share name")
    source.add_argument("--smb-path", default="", help="directory within the share")
    source.add_argument("--smb-user", help="SMB user")
    source.add_argument("--smb-password", help="SMB password")
    source.add_argument("--smb-domain", help="Active Directory domain for the SMB user")

    parser.add_argument("--definition-file",
                        help="name of the definition file to read "
                             "(default: the last element of the source path, plus .xml)")
    parser.add_argument("--format", default="",
                        help="disk image format; empty means qcow2")
    parser.add_argument("--no-non-sequential-writes", action="store_true",
                        help="disable non-sequential writes")
    parser.add_argument("--parallel-count-per-transfer", type=int,
                        help="number of parallel streams per disk transfer")

    cloudinit = parser.add_argument_group("cloud-init seed for the imported VM")
    cloudinit.add_argument("--user-data-file", help="path to a cloud-init user-data file")
    cloudinit.add_argument("--meta-data-file", help="path to a cloud-init meta-data file")

    args = parser.parse_args(argv)

    if not args.path_uri and not (args.smb_server and args.smb_share and args.smb_user):
        parser.error("give --path-uri, or --smb-server, --smb-share and --smb-user")
    return args


def resolve_credentials(args):
    username = args.username or os.environ.get("SC_USERNAME")
    password = args.password or os.environ.get("SC_PASSWORD")
    if not username:
        username = input("SC//HyperCore username: ")
    if not password:
        password = getpass.getpass("SC//HyperCore password: ")
    return username, password


def resolve_source_uri(args):
    """Return (pathURI, masked pathURI)."""
    if args.path_uri:
        return args.path_uri, mask_uri(args.path_uri)

    smb_password = args.smb_password
    if smb_password is None:
        smb_password = os.environ.get("SC_SMB_PASSWORD")
    if smb_password is None:
        smb_password = getpass.getpass("SMB password for {0}: ".format(args.smb_user))

    return build_smb_uri(
        args.smb_server, args.smb_share, args.smb_path,
        args.smb_user, smb_password, domain=args.smb_domain,
    )


def default_definition_file(path_uri):
    tail = path_uri.rstrip("/").rsplit("/", 1)[-1]
    return "{0}.xml".format(tail) if tail else "vm.xml"


def build_cloud_init(user_data_path, meta_data_path):
    """cloudInitData wants both halves base64-encoded."""
    cloud_init = {}
    for key, path in (("userData", user_data_path), ("metaData", meta_data_path)):
        if not path:
            continue
        with open(path, "rb") as handle:
            cloud_init[key] = base64.b64encode(handle.read()).decode("ascii")
    return cloud_init


def main(argv=None):
    args = parse_args(argv)
    username, password = resolve_credentials(args)
    path_uri, masked = resolve_source_uri(args)

    definition_file = args.definition_file or default_definition_file(path_uri)

    session = make_session(username, password)
    base = api_base(args.node, args.api_version)

    print("Importing a VM into {0}".format(args.node))
    print("  source:          {0}".format(masked))
    print("  definition file: {0}".format(definition_file))
    if args.name:
        print("  new VM name:     {0}".format(args.name))

    source = {
        "pathURI": path_uri,
        "definitionFileName": definition_file,
        "format": args.format,
    }
    if args.no_non_sequential_writes:
        source["allowNonSequentialWrites"] = False
    if args.parallel_count_per_transfer:
        source["parallelCountPerTransfer"] = args.parallel_count_per_transfer

    # `template` overrides fields of the VM being created. Leave it empty to
    # take everything from the definition file.
    template = {}
    if args.name:
        template["name"] = args.name
    cloud_init = build_cloud_init(args.user_data_file, args.meta_data_file)
    if cloud_init:
        template["cloudInitData"] = cloud_init

    payload = {"source": source, "template": template}

    try:
        result, task = post_and_wait(
            session, base, "/VirDomain/import", payload, label="import",
        )
    except (ApiError, TaskFailed) as exc:
        print("Import failed: {0}".format(exc), file=sys.stderr)
        return 1

    # The import task carries the new VM's UUID; the POST response does not
    # always populate createdUUID for this endpoint.
    new_uuid = result.get("createdUUID") or task.get("createdUUID")
    print("Import complete ({0}).".format(task.get("state")))
    if new_uuid:
        print("  new VM UUID: {0}".format(new_uuid))
        print("  The imported VM is stopped. Check its blockDevs before starting it --")
        print("  an import attaches an empty IDE_CDROM, and for a Windows operatingSystem")
        print("  it also attaches scale-guest-tools.iso.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
