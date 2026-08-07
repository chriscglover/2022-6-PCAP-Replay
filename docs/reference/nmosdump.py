#!/usr/bin/env python3
"""
nmos_tree_walker.py

Walk the IS-04 Node API on a given NMOS host, pull down every resource
type (self, devices, sources, flows, senders, receivers), and save the
raw JSON to disk. For senders, also fetches the manifest (SDP transport
file, if advertised) via manifest_href.

Usage:
    python3 nmos_tree_walker.py --host 192.168.1.50
    python3 nmos_tree_walker.py --host node.example.com --port 8080 --version v1.3
    python3 nmos_tree_walker.py --host 192.168.1.50 --https --insecure
    python3 nmos_tree_walker.py --host 192.168.1.50 --connection --out ./capture

Notes:
    - Auto-discovers the highest supported API version unless --version is given.
    - Resource collections (devices/sources/flows/senders/receivers) are saved
      both as a single combined JSON array and as one file per resource (by id).
    - With --connection, also queries the IS-05 Connection API (active/staged/
      constraints/transporttype) for every sender and receiver, if present.
"""

import argparse
import json
import os
import sys
from urllib.parse import urljoin

import requests

RESOURCE_TYPES = ["devices", "sources", "flows", "senders", "receivers"]


def get_json(session, url, timeout):
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def safe_id(resource, fallback):
    return resource.get("id", fallback)


def discover_version(session, base, timeout, requested):
    """Return the API version path segment to use, e.g. 'v1.3'."""
    if requested:
        return requested
    versions = get_json(session, base, timeout)  # e.g. ["v1.0/", "v1.1/", ... ]
    versions = [v.strip("/") for v in versions]
    if not versions:
        raise RuntimeError("Node API root returned no versions")
    # sort by (major, minor) numerically, take highest
    def key(v):
        v = v.lstrip("v")
        parts = v.split(".")
        return tuple(int(p) for p in parts)
    versions.sort(key=key)
    return versions[-1]


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def walk_node_api(session, node_base, out_dir, timeout, verbose):
    """node_base like http://host:port/x-nmos/node/v1.3/"""

    # --- self ---
    self_doc = get_json(session, urljoin(node_base, "self"), timeout)
    save_json(os.path.join(out_dir, "self", "self.json"), self_doc)
    if verbose:
        print(f"[self] saved node self document (id={self_doc.get('id')})")

    collected = {}

    for rtype in RESOURCE_TYPES:
        url = urljoin(node_base, rtype)
        try:
            items = get_json(session, url, timeout)
        except requests.HTTPError as e:
            print(f"[{rtype}] WARNING: {e}", file=sys.stderr)
            continue

        collected[rtype] = items
        type_dir = os.path.join(out_dir, rtype)

        # combined array
        save_json(os.path.join(type_dir, f"_all_{rtype}.json"), items)

        # individual resources
        for idx, item in enumerate(items):
            rid = safe_id(item, f"unknown_{idx}")
            save_json(os.path.join(type_dir, f"{rid}.json"), item)

        if verbose:
            print(f"[{rtype}] saved {len(items)} resource(s)")

    return self_doc, collected


def fetch_sender_manifests(session, node_base, senders, out_dir, timeout, verbose):
    """Fetch each sender's manifest_href (typically an SDP transport file)."""
    manifest_dir = os.path.join(out_dir, "senders", "manifests")
    os.makedirs(manifest_dir, exist_ok=True)

    for sender in senders:
        sid = sender.get("id", "unknown")
        href = sender.get("manifest_href")
        if not href:
            continue

        # manifest_href may be relative or absolute
        url = urljoin(node_base, href) if not href.startswith("http") else href

        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"[manifest] WARNING sender {sid}: {e}", file=sys.stderr)
            continue

        # SDP files are text/sdp; fall back to .txt if content-type is odd
        ctype = resp.headers.get("Content-Type", "")
        ext = "sdp" if "sdp" in ctype.lower() or href.endswith(".sdp") else "manifest"
        path = os.path.join(manifest_dir, f"{sid}.{ext}")
        with open(path, "w") as f:
            f.write(resp.text)

        if verbose:
            print(f"[manifest] saved sender {sid} -> {os.path.basename(path)}")


def walk_connection_api(session, conn_base, senders, receivers, out_dir, timeout, verbose):
    """conn_base like http://host:port/x-nmos/connection/v1.1/"""
    subpaths = ["active", "staged", "constraints", "transporttype"]

    for role, resources in (("senders", senders), ("receivers", receivers)):
        for res in resources:
            rid = res.get("id")
            if not rid:
                continue
            for sub in subpaths:
                url = urljoin(conn_base, f"single/{role}/{rid}/{sub}")
                try:
                    data = get_json(session, url, timeout)
                except requests.RequestException as e:
                    print(f"[connection:{role}/{sub}] WARNING {rid}: {e}", file=sys.stderr)
                    continue
                path = os.path.join(out_dir, "connection", role, rid, f"{sub}.json")
                save_json(path, data)

        if verbose:
            print(f"[connection] queried {role}: {len(resources)} resource(s)")


def main():
    ap = argparse.ArgumentParser(description="Walk an NMOS Node API and save all resources to disk.")
    ap.add_argument("--host", required=True, help="NMOS node hostname or IP")
    ap.add_argument("--port", type=int, default=80, help="Port (default 80, or 443 with --https)")
    ap.add_argument("--https", action="store_true", help="Use https instead of http")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS cert verification (https only)")
    ap.add_argument("--version", default=None, help="API version, e.g. v1.3 (default: auto-discover highest)")
    ap.add_argument("--out", default=None, help="Output directory (default: ./nmos_capture_<host>)")
    ap.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    ap.add_argument("--no-manifests", action="store_true", help="Skip fetching sender SDP/manifest files")
    ap.add_argument("--connection", action="store_true",
                     help="Also walk the IS-05 Connection API for active/staged/constraints/transporttype")
    ap.add_argument("--connection-version", default=None,
                     help="Connection API version, e.g. v1.1 (default: auto-discover highest)")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    args = ap.parse_args()

    scheme = "https" if args.https else "http"
    port = args.port if args.port != 80 or not args.https else args.port
    root = f"{scheme}://{args.host}:{port}/x-nmos/"
    node_root = urljoin(root, "node/")
    conn_root = urljoin(root, "connection/")

    out_dir = args.out or f"./nmos_capture_{args.host.replace(':', '_')}"
    verbose = not args.quiet

    session = requests.Session()
    if args.insecure:
        session.verify = False
        requests.packages.urllib3.disable_warnings()

    try:
        node_version = discover_version(session, node_root, args.timeout, args.version)
    except Exception as e:
        print(f"ERROR: could not reach/parse Node API at {node_root}: {e}", file=sys.stderr)
        sys.exit(1)

    node_base = urljoin(node_root, f"{node_version}/")
    if verbose:
        print(f"Node API: {node_base}")
        print(f"Output dir: {out_dir}")

    self_doc, collected = walk_node_api(session, node_base, out_dir, args.timeout, verbose)

    if not args.no_manifests:
        senders = collected.get("senders", [])
        if senders:
            fetch_sender_manifests(session, node_base, senders, out_dir, args.timeout, verbose)

    if args.connection:
        try:
            conn_version = discover_version(session, conn_root, args.timeout, args.connection_version)
            conn_base = urljoin(conn_root, f"{conn_version}/")
            if verbose:
                print(f"Connection API: {conn_base}")
            walk_connection_api(
                session, conn_base,
                collected.get("senders", []), collected.get("receivers", []),
                out_dir, args.timeout, verbose,
            )
        except Exception as e:
            print(f"WARNING: Connection API not walked: {e}", file=sys.stderr)

    if verbose:
        counts = {k: len(v) for k, v in collected.items()}
        print("\nDone.")
        print(f"  self: 1")
        for k, v in counts.items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
