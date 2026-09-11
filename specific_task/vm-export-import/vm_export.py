#!/usr/bin/env python3
"""
vm_export.py

Export a VM from an SC//HyperCore(TM) cluster to an SMB share, using
POST /rest/v1/VirDomain/{uuid}/export.

An export writes two things into the target directory: a definition file
(XML) describing the VM, and one qcow2 file per disk. That directory is what
vm_import.py reads back.

Usage
    # export a VM to an SMB share (validated against a stopped VM)
    ./vm_export.py --node 10.0.0.1 --vm-name my-vm \
        --smb-server 10.0.0.50 --smb-share exports --smb-path hcexports/my-vm \
        --smb-user administrator --smb-password 'secret'

    # Active Directory domain account
    ./vm_export.py ... --smb-domain example.local

    # export a point-in-time snapshot instead of the VM's current state
    ./vm_export.py ... --snapshot-uuid 1b0e...

    # pass a complete pathURI yourself instead of the --smb-* options
    ./vm_export.py --node 10.0.0.1 --vm-name my-vm \
        --path-uri 'smb://administrator:secret@10.0.0.50/exports/hcexports/my-vm'

Credentials are read from the SC_USERNAME / SC_PASSWORD environment variables
when --username / --password are not given, and prompted for otherwise.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""

import argparse
import getpass
import os
import sys

from hypercore_transfer import (
    ApiError,
    TaskFailed,
    api_base,
    build_smb_uri,
    find_vm,
    make_session,
    mask_uri,
    post_and_wait,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Export an SC//HyperCore VM to an SMB share.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--node", required=True, help="cluster node IP or FQDN")
    parser.add_argument("--username", help="cluster user (default $SC_USERNAME)")
    parser.add_argument("--password", help="cluster password (default $SC_PASSWORD, else prompt)")
    parser.add_argument("--api-version", default="v1", choices=("v1", "v2"),
                        help="REST API version; an http:// pathURI needs v2")

    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--vm-name", help="name of the VM to export")
    which.add_argument("--vm-uuid", help="UUID of the VM to export")

    parser.add_argument("--snapshot-uuid",
                        help="export this VirDomainSnapshot instead of the VM's live state")

    target = parser.add_argument_group("export target (use --path-uri OR the --smb-* options)")
    target.add_argument("--path-uri", help="complete pathURI, credentials included")
    target.add_argument("--smb-server", help="SMB server IP or hostname")
    target.add_argument("--smb-share", help="SMB share name")
    target.add_argument("--smb-path", default="", help="directory within the share")
    target.add_argument("--smb-user", help="SMB user")
    target.add_argument("--smb-password", help="SMB password")
    target.add_argument("--smb-domain", help="Active Directory domain for the SMB user")

    parser.add_argument("--definition-file",
                        help="name of the definition file to write "
                             "(default: the last element of the target path, plus .xml)")
    parser.add_argument("--compress", action="store_true",
                        help="compress the exported disk images (smaller, slower)")
    parser.add_argument("--format", default="",
                        help="disk image format; empty means qcow2")
    parser.add_argument("--no-non-sequential-writes", action="store_true",
                        help="disable non-sequential writes (they are on by default and "
                             "usually faster, but some SMB servers do not handle them)")
    parser.add_argument("--parallel-count-per-transfer", type=int,
                        help="number of parallel streams per disk transfer")

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


def resolve_target_uri(args):
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
    """Derive the definition file name from the last element of the target path.

    Keeping the definition file named after its directory means vm_import.py
    can be pointed at the directory alone, and it is the convention the
    cluster's own UI follows.
    """
    tail = path_uri.rstrip("/").rsplit("/", 1)[-1]
    return "{0}.xml".format(tail) if tail else "vm.xml"


def main(argv=None):
    args = parse_args(argv)
    username, password = resolve_credentials(args)
    path_uri, masked = resolve_target_uri(args)

    definition_file = args.definition_file or default_definition_file(path_uri)

    session = make_session(username, password)
    base = api_base(args.node, args.api_version)

    vm = find_vm(session, base, name=args.vm_name, uuid=args.vm_uuid)
    print("Exporting VM {0!r} ({1}) from {2}".format(vm["name"], vm["uuid"], args.node))
    print("  target:          {0}".format(masked))
    print("  definition file: {0}".format(definition_file))

    # Only pathURI is required. compress and format are always sent, at their
    # defaults, because both are harmless to state explicitly; the two below
    # them go only when asked for, so the cluster's own defaults apply.
    target = {
        "pathURI": path_uri,
        "definitionFileName": definition_file,
        "compress": bool(args.compress),
        "format": args.format,
    }
    if args.no_non_sequential_writes:
        target["allowNonSequentialWrites"] = False
    if args.parallel_count_per_transfer:
        target["parallelCountPerTransfer"] = args.parallel_count_per_transfer

    payload = {"target": target}
    if args.snapshot_uuid:
        payload["snapUUID"] = args.snapshot_uuid

    try:
        _, task = post_and_wait(
            session, base,
            "/VirDomain/{0}/export".format(vm["uuid"]),
            payload, label="export",
        )
    except (ApiError, TaskFailed) as exc:
        print("Export failed: {0}".format(exc), file=sys.stderr)
        return 1

    print("Export complete ({0}).".format(task.get("state")))
    print("Import it back with:")
    print("  ./vm_import.py --node {0} --path-uri '<same pathURI>' "
          "--definition-file {1} --name <new-vm-name>".format(args.node, definition_file))
    return 0


if __name__ == "__main__":
    sys.exit(main())
