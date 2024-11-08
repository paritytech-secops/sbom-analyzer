#! /usr/bin/env python3
from lib.logging import get_colored_logger
from lib4sbom.parser import SBOMParser

import re
import requests
import argparse
import csv
import datetime

from enum import StrEnum
from urllib.parse import unquote

logger = get_colored_logger("SBOM-Analyzer")

REPO_URL_REGEX = re.compile(r'^https://[\w]+\.[\w]+/([^/]+)/([^/]+)[/\w]*$')
PURL_REGEX = re.compile(r'^pkg:(\w+)/([%\w/\.-]+)@?([0-9a-fA-F\.%]*).*$')
CRATES_INPUT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"
OUTPUT_DATE_FORMAT = "%Y-%m-%d"
MAX_REGISTRY_FAILED_REQUESTS = 3
DOWNLOADS_DEPTH_DAYS = 7

class PackageType(StrEnum):
    CARGO = "cargo"
    NPM = "npm"
    GHA = "githubactions"
    PYPI = "pypi"
    GITHUB = "github"

class Package:
    def __init__(self, package_type: PackageType=None, name: str=None, version: str=None):
        self._name:str = name
        self._version:str = version
        self._package_type:PackageType = package_type

        self._downloads:int = 0
        self._lib_owners:set[str] = set()
        self._repo_owner:str = None
        self._repo_name:str = None
        self._repo_url:str = None
        self._last_push_date:datetime = None
        self._last_push_author:str = None

    def from_purl(self, purl: str, sbom_dict: dict = None) -> None:
        match = PURL_REGEX.match(purl)
        if match:
            self._package_type = match.group(1)
            self._name = unquote(match.group(2))
            self._version = unquote(match.group(3))
            if not self._version and sbom_dict:
                self._version = unquote(sbom_dict.get('version', str()))

    @property
    def name(self) -> str:
        return self._name
    
    @property
    def version(self) -> str:
        return self._version
    
    @property
    def package_type(self) -> PackageType:
        return self._package_type

    @property
    def downloads(self) -> int:
        return self._downloads
    
    @property
    def last_push_date(self) -> datetime:
        return self._last_push_date
    
    @property
    def last_push_author(self) -> str:
        return self._last_push_author

    @property
    def repo_owner(self) -> str:
        return self._repo_owner
    
    @property
    def repo_name(self) -> str:
        return self._repo_name

    @property
    def repo_url(self) -> str:
        return self._repo_url

    @property
    def owners(self) -> str:
        return ", ".join(self._lib_owners)

    def add_lib_owner(self, lib_owner: str) -> None:
        self._lib_owners.add(lib_owner)

    def set_repo_url(self, repo_url: str) -> None:
        if repo_url:
            self._repo_url = repo_url
            match = REPO_URL_REGEX.match(repo_url)
            if match:
                self._repo_owner = match.group(1)
                self._repo_name = match.group(2)
        else:
            logger.warning(f"Invalid repo URL: {repo_url} for repo {self.name}")

    def fill_package_metadata(self) -> None:
        for i in range(MAX_REGISTRY_FAILED_REQUESTS):
            try:
                if self.package_type == PackageType.CARGO:
                    #DO NOT make crates.io API calls too often, it will be rate limited and banned
                    #DO NOT use any threading for that, make them sequential
                    cargo_api_url = f"https://crates.io/api/v1/crates/{self.name}"
                    response = requests.get(cargo_api_url)
                    if response.status_code == 200:
                        data = response.json()
                        logger.debug(f"Got cargo metadata for {self.name}")
                        repo_url = data['crate']['repository']
                        repo_homepage = data['crate']['homepage']
                        self.set_repo_url(repo_url if repo_url else repo_homepage)
                        if self.version:
                            for index, crate in enumerate(data['versions']):
                                if crate['num'] == self.version or index == 0:
                                    self._last_push_date = datetime.datetime.strptime(crate['created_at'], 
                                                                                      CRATES_INPUT_DATE_FORMAT)
                                    self._last_push_author = crate['published_by'].get('login', None) \
                                        if crate['published_by'] else None
                                    break
                        cargo_owners_url = f"https://crates.io/api/v1/crates/{self.name}/owners"
                        owners_response = requests.get(cargo_owners_url)
                        if owners_response.status_code == 200:
                            users_data = owners_response.json()
                            for owner in users_data['users']:
                                owner_login = owner['login']
                                owner_name = owner['name']
                                self.add_lib_owner(f"{owner_login} ({owner_name})")
                        else:
                            logger.warning(f"Error fetching cargo owners for {self.name}: {owners_response.status_code}")
                        downloads_url = f"https://crates.io/api/v1/crates/{self.name}/downloads"
                        downloads_response = requests.get(downloads_url)
                        if downloads_response.status_code == 200:
                            downloads_data = downloads_response.json()
                            self._downloads = 0
                            for index, download in enumerate(downloads_data['meta']['extra_downloads']):
                                if index == DOWNLOADS_DEPTH_DAYS:
                                    break
                                self._downloads += download['downloads']
                        else:
                            logger.warning(f"Error fetching cargo downloads for {self.name}: {downloads_response.status_code}")
                        break
                #TODO: Add NPM, PyPI, GitHub, GitHub Actions metadata fetching
            except Exception as e:
                logger.warning(f"Error fetching cargo metadata for {self.name}: {e}, attempt {i + 1}")


def main():
    parser = argparse.ArgumentParser(description='SBOM Analyzer')
    parser.add_argument('input_file', help='Path to input JSON SBOM file')
    parser.add_argument('--output', help='Path to output CSV file',
                        type=argparse.FileType('w'), default='-')
    args = parser.parse_args()
    parser = SBOMParser()
    parser.parse_file(args.input_file)
    packages = parser.get_packages()
    parsed_packages = []
    packages_headers = ["PackageType", 
                        "PackageName", 
                        "Version", 
                        "RepoURL",
                        "RepoOwner",
                        "RepoName",
                        "PackageOwners",
                        "7DaysDownloads", 
                        "LastPackagePushDate", 
                        "LastPackagePushAuthor", 
                        ]
    for package in packages:
        pkg = Package()
        pkg.from_purl(package['externalreference'][0][2], package)
        logger.debug(f"Analyzing package Type:{pkg.package_type} Name:{pkg.name} Version:{pkg.version}...")
        pkg.fill_package_metadata()
        parsed_packages.append([pkg.package_type, 
                                pkg.name, 
                                pkg.version, 
                                pkg.repo_url, 
                                pkg.repo_owner,
                                pkg.repo_name,
                                pkg.owners,
                                pkg.downloads, 
                                pkg.last_push_date.strftime(OUTPUT_DATE_FORMAT) if pkg.last_push_date else None, 
                                pkg.last_push_author])
    with args.output as output_file:
        writer = csv.writer(output_file)
        writer.writerow(packages_headers)
        writer.writerows(parsed_packages)

if __name__ == "__main__":
    main()
