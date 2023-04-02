import argparse

from dataclasses import dataclass
import hashlib
import logging
import typing
import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


@dataclass
class CompareSpecification:
    etag: typing.Optional[str] = None
    sha512: typing.Optional[str] = None

    # def __dict__(self):
    #     return {
    #         key: value
    #         for key, value in [("etag", self.etag), ("sha512", self.sha512)]
    #         if value
    #     }

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

    # def __dict__(self):
    #     return dict(name=self.name, href=self.href, compare=self.compare)

    @classmethod
    def from_json(json):
        return __class__(
            json["name"], json["href"], CompareSpecification(*json["compare"])
        )


PAGES = [
    MonitoredPage(
        "curl",
        "https://curl.se/docs/security.html",
        CompareSpecification(etag='"abf1-5f7917bea1fed-gzip"'),
    ),
    MonitoredPage(
        "OpenSSL",
        "https://www.openssl.org/news/vulnerabilities.html",
        CompareSpecification(
            sha512=(
                "d5c025ff8877614dbb89194f7318c392",
                "267e7a57e7b3c7cc235464f324b6cc3c",
                "bdabe1b6a6fc1eb4836350efbf4f582c",
                "34399c9bb8c2465c5ba9fb9ee01b1994",
            ),
        ),
    ),
]


def create_parser():
    parser = argparse.ArgumentParser()


def main():
    for page_spec in PAGES:
        response = requests.get(page_spec.href)
        if not page_spec.compare(response):
            print(f"Page for {page_spec.name} did not pass comparison.")


if __name__ == "__main__":
    main()
