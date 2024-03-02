"""
"""

from mapper import Website, WebsiteOptions
from argparse import ArgumentParser


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--do-headless', action='store_true', default=True)
    parser.add_argument('--skip-subdomain', action='store_true', default=True)
    parser.add_argument('--skip-url-args', action='store_true', default=True)
    parser.add_argument('--skip-other-domain', action='store_true', default=True)
    parser.add_argument('--skip-navtags', action='store_true', default=True)
    parser.add_argument('--skip-screenshot', action='store_true', default=True)
    parser.add_argument('--screenshot-folder', type=str, default='screenshots')
    parser.add_argument('--thread-count', type=int, default=10)
    parser.add_argument('--url', type=str, default='https://www.python.org/')
    args = parser.parse_args()

    options = WebsiteOptions(skip_screenshot=False, skip_subdomain=False)
    website = Website(
        args.url,
        options=WebsiteOptions(
            do_headless=args.do_headless,
            skip_subdomain=args.skip_subdomain,
            skip_url_args=args.skip_url_args,
            skip_other_domain=args.skip_other_domain,
            skip_navtag=args.skip_navtags,
            skip_screenshot=args.skip_screenshot,
            screenshot_folder=args.screenshot_folder
        )
    )
    website.load(thread_count=args.thread_count)
