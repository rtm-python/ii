"""
"""

import logging

from mapper import Website, WebsiteOptions
from argparse import ArgumentParser

logger = logging.getLogger('AGENT')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s | %(name)s:%(levelname)s | %(message)s | %(module)s:%(funcName)s:%(lineno)d')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
logger.addHandler(handler)


if __name__ == '__main__':
    # from mapper import verify_url_as_html
    # file = 'https://www.python.org/ftp/python/3.6.2/amd64'

    # print(verify_url_as_html(file))

    # exit(0)

    parser = ArgumentParser()
    parser.add_argument('--do-headless', action='store_true', default=True)
    parser.add_argument('--skip-subdomain', action='store_true', default=True)
    parser.add_argument('--skip-upper-path', action='store_true', default=True)
    parser.add_argument('--skip-url-args', action='store_true', default=True)
    parser.add_argument('--skip-other-domain', action='store_true', default=True)
    parser.add_argument('--skip-navtags', action='store_true', default=True)
    parser.add_argument('--skip-screenshot', action='store_true', default=True)
    parser.add_argument('--screenshot-folder', type=str, default='screenshots')
    parser.add_argument('--thread-count', type=int, default=10)
    parser.add_argument('--url', type=str, default='https://www.python.org/')
    args = parser.parse_args()
    for (name, value) in args.__dict__.items():
        if not name.startswith('__'):
            logger.info(f'{name} = {value}')

    options = WebsiteOptions(skip_screenshot=False, skip_subdomain=False)
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
            screenshot_folder=args.screenshot_folder
        )
    )
    website.load(thread_count=args.thread_count)
    logger.info(f'"{args.url}" loaded: {len(website.webpages.items())} webpages')
