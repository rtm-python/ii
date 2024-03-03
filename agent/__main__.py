"""
"""

import logging

from mapper import Website, WebsiteOptions
from argparse import ArgumentParser


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('--do-headless', action='store_true', default=False)
    parser.add_argument('--skip-subdomain', action='store_true', default=False)
    parser.add_argument('--skip-upper-path', action='store_true', default=False)
    parser.add_argument('--skip-url-args', action='store_true', default=False)
    parser.add_argument('--skip-other-domain', action='store_true', default=False)
    parser.add_argument('--skip-navtags', action='store_true', default=False)
    parser.add_argument('--skip-screenshot', action='store_true', default=False)
    parser.add_argument('--screenshot-folder', type=str, default='screenshots')
    parser.add_argument('--screenshot-width', type=int, default=800)
    parser.add_argument('--thread-count', type=int, default=10)
    parser.add_argument('--url', type=str, default='https://www.python.org/')
    parser.add_argument('--search-text', type=str, default=None)
    args = parser.parse_args()

    logger = logging.getLogger('AGENT')
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s | %(name)s:%(levelname)s | %(message)s | %(module)s:%(funcName)s:%(lineno)d')
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
    logger.addHandler(handler)

    for (name, value) in args.__dict__.items():
        if not name.startswith('__'):
            logger.info(f'{name} = {value}')

    website = Website(
        args.url,
        options=WebsiteOptions(
            do_headless=args.do_headless,
            skip_subdomain=args.skip_subdomain,
            skip_upper_path=args.skip_upper_path,
            skip_url_args=args.skip_url_args,
            skip_other_domain=args.skip_other_domain,
            skip_navtag=args.skip_navtags,
            skip_screenshot=args.skip_screenshot,
            screenshot_folder=args.screenshot_folder,
            screenshot_width=args.screenshot_width,
            search_text=args.search_text
        )
    )
    website.load(thread_count=args.thread_count)
    logger.info(f'"{args.url}" loaded: {len(website.webpages.items())} webpages')
    if args.search_text is not None:
        logger.info(f'"{args.search_text}" found in {len(website.search_match_urls)} webpages')
        for url in website.search_match_urls:
            logger.info(f'[+] {url}')
