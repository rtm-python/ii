"""

"""

import asyncio
import httpx
import logging
import json

from mapper import Webpage
from argparse import ArgumentParser
from urllib.parse import urlparse


def getLogger(name: str, level: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.level)

    handler = logging.StreamHandler()
    handler.setLevel(logging.level)

    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger



async def read(url: str):
    async with httpx.AsyncClient() as client:
        return await client.get(url)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--headless', action='store_true', default=False)
    parser.add_argument('--ignore-navtags', action='store_true', default=False)
    parser.add_argument('--skip-screenshot', action='store_true', default=False)
    parser.add_argument('--skip-subdomain', action='store_true', default=False)
    parser.add_argument('--skip-url-args', action='store_true', default=False)
    parser.add_argument('--within-domain', action='store_true', default=False)
    parser.add_argument('--url', type=str, default='https://www.python.org/')
    args = parser.parse_args()

    try:
        logging.basicConfig(level=logging.INFO)
        domain = urlparse(args.url).netloc
        webpage = Webpage(args.url, None)
        webpage.discover(
            do_headless=args.headless,
            skip_screenshot=args.skip_screenshot,
            ignore_navtags=args.ignore_navtags,
            skip_subdomain=args.skip_subdomain,
            skip_url_args=args.skip_url_args,
            within_domain=domain if args.within_domain else None
        )
        logging.info(json.dumps(webpage.json(), indent=2))

    except KeyboardInterrupt:
        pass
