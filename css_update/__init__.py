# Copyright (C) 2025  Sisyphus1813
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import io
import asyncio
import aiohttp
import zipfile
import argparse

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--update-persistent",
    help="Update both recent and persistent stored hashes",
    action="store_true",
)
group.add_argument(
    "--update-recent",
    help="Update only recent stored hashes",
    action="store_true",
)
group.add_argument(
    "--update-yara",
    help="Update only YARA rules",
    action="store_true",
)
parser.add_argument(
    "--yara",
    help="Also update YARA rules (can be used alone or with update flags)",
    action="store_true",
)

PERSISTENT_SOURCES = {
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
    "https://bazaar.abuse.ch/export/txt/md5/full/",
    "https://bazaar.abuse.ch/export/txt/sha1/full/"
}

RECENT_SOURCES = {
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-md5-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha1-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt",
    "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "https://bazaar.abuse.ch/export/txt/md5/recent/",
    "https://bazaar.abuse.ch/export/txt/sha1/recent/"
}

YARA_SOURCES = {
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
}

async def fetch_yara(session, source):
    async with session.get(source) as response:
        data = await response.read()
        with zipfile.ZipFile(io.BytesIO(data)) as zip:
            for name in zip.namelist():
                if name.endswith(".yar"):
                    with zip.open(name) as source, open(f"/var/lib/css/yara_rules/{os.path.basename(name)}", "wb") as destination:
                        destination.write(source.read())

async def fetch(session, source):
    async with session.get(source) as response:
        if response.content_type == "application/zip":
            data = await response.read()
            with zipfile.ZipFile(io.BytesIO(data)) as zip:
                hashes = set()
                for name in zip.namelist():
                    with zip.open(name) as f:
                        for line in f:
                            line = line.decode("utf-8").strip()
                            if line:
                                hashes.add(line)
                return hashes
        else:
            return set((await response.text()).splitlines())

async def poll(sources):
    async with aiohttp.ClientSession() as session:
        if sources == YARA_SOURCES:
            await asyncio.gather(*(fetch_yara(session, source) for source in YARA_SOURCES))
            return
        else:
            tasks = [fetch(session, src) for src in sources]
            results = await asyncio.gather(*tasks)
            return set().union(*results)

def save(hashes, persistent=False):
    hashes = {hash for hash in hashes if "#" not in hash}
    if persistent:
        with open("/var/lib/css/hashes/persistent_hashes.txt", "w") as f:
            for hash in sorted(hashes):
                f.write(f"{hash}\n")
    else:
        with open("/var/lib/css/hashes/hashes.txt", "w") as f:
            for hash in sorted(hashes):
                f.write(f"{hash}\n")

async def update(persistent=False):
    if not os.path.isfile("/var/lib/css/hashes/persistent_hashes.txt") or persistent:
        persistent_hashes = await poll(PERSISTENT_SOURCES)
        save(persistent_hashes, True)
    hashes = await poll(RECENT_SOURCES)
    save(hashes)

def main():
    os.makedirs("/var/lib/css/hashes/", exist_ok=True)
    os.makedirs("/var/lib/css/yara_rules/", exist_ok=True)
    if not os.path.isfile("/etc/css/directories_monitor.json"):
        os.makedirs("/etc/css/", exist_ok=True)
        with open("/etc/css/directories_monitor.json", "w") as f:
            f.write('{ "directories": [] }')
    args = parser.parse_args()
    if not os.listdir("/var/lib/css/yara_rules/") and not args.update_yara and not args.yara:
        asyncio.run(poll(YARA_SOURCES))
    elif os.listdir("/var/lib/css/yara_rules/") and (args.update_yara or args.yara):
        for file in os.listdir("/var/lib/css/yara_rules/"):
            os.remove(f"/var/lib/css/yara_rules/{file}")
    match True:
        case _ if args.update_recent:
            asyncio.run(update())
        case _ if args.update_persistent:
            asyncio.run(update(True))
        case _ if args.update_yara:
            asyncio.run(poll(YARA_SOURCES))
            return
    if args.yara:
        asyncio.run(poll(YARA_SOURCES))
