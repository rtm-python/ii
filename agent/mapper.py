

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import StaleElementReferenceException

import numpy
import cv2
import logging
import time

from typing import List
from dataclasses import dataclass
from dataclasses import field
from urllib.parse import urlparse

NAVTAG = '#'
URL_ENDING_SLASH = '/'
SCREENSHOT_SIZE_COEF = 0.3


def take_body_screenshot(driver) -> numpy.ndarray:
    body = driver.find_elements(By.TAG_NAME, 'body')[0]
    png = body.screenshot_as_png
    bytes = numpy.frombuffer(png, dtype=numpy.uint8)
    screenshot = cv2.imdecode(bytes, cv2.IMREAD_COLOR)
    height, width, _ = screenshot.shape
    return cv2.resize(
        screenshot,
        (
            int(width * SCREENSHOT_SIZE_COEF),
            int(height * SCREENSHOT_SIZE_COEF)
        )
    )


def fix_url_ending_slash(url: str) -> str:
    return url[: -1] if url.endswith(URL_ENDING_SLASH) else url


@dataclass
class Webpage:
    url: str
    parent: "Webpage"
    load_seconds: float = None
    webpages: List["Webpage"] = field(default_factory=list)
    screenshot: numpy.ndarray = None

    def __post_init__(self):
        self.url = fix_url_ending_slash(self.url)

    def discover(self, parent_driver = None, ignore_navtags: bool = True,
                 skip_screenshot: bool = True, do_headless: bool = True,
                 skip_subdomain: bool = True, skip_url_args: bool = True,
                 within_domain: str = None) -> bool:

        domain = urlparse(self.url).netloc

        try:
            if parent_driver is not None:
                driver = parent_driver

            else:
                options = FirefoxOptions()
                if do_headless:
                    options.add_argument("--headless")

                driver = webdriver.Firefox(options=options)

            time_before = time.perf_counter()
            driver.get(self.url)
            
            time_after = time.perf_counter()
            self.load_seconds = time_after - time_before
            logging.info(f'[ {self.load_seconds:2f} ] {self.url}')

            if not skip_screenshot:
                self.screenshot = take_body_screenshot(driver)

            hrefs = []
            for link in driver.find_elements(By.TAG_NAME, "a"):
                try:
                    href = link.get_attribute("href")
                    if href is None or href == "":
                        continue
                    hrefs += [ fix_url_ending_slash(href) ]
                
                except StaleElementReferenceException:
                    continue

            for href in hrefs:
                if ignore_navtags and NAVTAG in href:
                    continue
                href_domain = urlparse(href).netloc
                if within_domain is not None and \
                        not href_domain.endswith(within_domain):
                    continue
                if skip_subdomain and not domain == href_domain:
                    continue
                if skip_url_args and '?' in href:
                    continue
            
                if not self.is_circular(href):
                    webpage = Webpage(href, self)
                    if webpage.discover(
                                driver,
                                skip_screenshot=skip_screenshot,
                                ignore_navtags=ignore_navtags,
                                do_headless=do_headless,
                                skip_subdomain=skip_subdomain,
                                skip_url_args=skip_url_args,
                                within_domain=within_domain
                            ):
                        self.webpages += [ webpage ]
            
        except Exception as exc:
            logging.info(f'{self}: {self.webpages}')
            logging.error(exc)
            return False

        finally:
            if parent_driver is None:
                driver.quit()
                driver.close()

        return True

    def is_circular(self, url: str) -> bool:
        if self.url == url:
            return True
        if self.parent is None:
            return False
        elif self.parent.url == url:
            return True
        for webpage in self.webpages:
            if webpage.url == url:
                return True
        return self.parent.is_circular(url)

    def json(self) -> dict:
        return {
            "url": self.url,
            "webpages": [ webpage.json() for webpage in self.webpages ],
        }

    def __str__(self) -> str:
        return self.url
