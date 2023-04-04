import argparse

from dataclasses import dataclass
import hashlib
import logging
import json
import typing
import os
import requests

logger = logging.getLogger(__name__)


@dataclass
class CompareSpecification:
    etag: typing.Optional[str] = None
    sha512: typing.Optional[str] = None

    def __call__(self, response: requests.Response):
        response.raise_for_status()
        if self.etag is not None:
            logger.debug("Response etag: %r", response.headers["etag"])
            return response.headers["etag"] == self.etag
        if self.sha512 is not None:
            response_hash = hashlib.sha512(response.content).hexdigest()
            logger.debug("Response hash: %s", response_hash)
            return response_hash == self.sha512


@dataclass
class MonitoredPage:
    name: str
    href: str
    compare: CompareSpecification

    def monitor(self):
        response = requests.get(self.href)
        return self.compare(response)

    @classmethod
    def from_json(cls, json):
        return cls(json["name"], json["href"], CompareSpecification(**json["compare"]))


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json-database",
        help="JSON file to load webpage database from",
        type=argparse.FileType("r"),
        default=os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "examples", "pages.json"
        ),
    )
    parser.add_argument(
        "--log-level",
        choices=(
            logging.DEBUG,
            logging.INFO,
            logging.WARNING,
            logging.ERROR,
            logging.CRITICAL,
        ),
        default=logging.INFO,
        help="Logging level chosen from Python's logging module",
        type=int,
    )
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    logger.setLevel(args.log_level)
    logger.addHandler(logging.StreamHandler())

    PAGES = [MonitoredPage.from_json(x) for x in json.load(args.json_database)]
    for page in PAGES:
        logger.debug("Processing %s", page.name)
        if not page.monitor():
            print(f"---- {page.name} ----")
            print(f"Page for {page.name} does not matched saved state.")
            print(f"Check {page.href} for changes.")


if __name__ == "__main__":
    main()
