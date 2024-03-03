"""
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import StaleElementReferenceException

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import httpx
import logging
import time
import os
import ssl

from typing import List
from dataclasses import dataclass
from dataclasses import field
from urllib.parse import urlparse
from uuid import uuid4

from threading import Thread, Event, Lock
from queue import Queue, Empty

NAVTAG = '#'
URL_ENDING_SLASH = '/'

logger = logging.getLogger('AGENT')


def remove_url_ending_slash(url: str) -> str:
    """
    Returns the URL with the trailing slash removed if present.

    Removes any trailing '/' character from the end of the URL string.
    """
    return url[: -1] if url.endswith(URL_ENDING_SLASH) else url


def save_body_screenshot(browser, folder: str) -> str:
    """
    Saves a screenshot of the browser body element to a PNG file.

    Parameters:
    browser (WebDriver): The Selenium WebDriver instance. 
    folder (str): The folder path to save the screenshot to.

    Returns:
    str: The filename of the saved screenshot.
    """
    filename = str(uuid4())
    filepath = os.path.join(folder, f'{filename}.png')
    body = browser.find_elements(By.TAG_NAME, 'body')
    if len(body) == 0:
        raise ValueError(f'No element <body> on "{browser.current_url}"')        
    with open(filepath, "wb") as file:
        file.write(body[0].screenshot_as_png)
    return filename


def verify_url_as_html(url: str) -> bool:
    """
    Verifies that the given URL returns an HTML content type 
    in the response headers when requested.

    Parameters:
    url (str): The URL to request and verify.

    Returns:
    bool: True if the URL returns HTML, False otherwise.

    """
    try:
        with httpx.Client(verify=True) as client:
            response = client.head(url, follow_redirects=True)
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type:
                return False
    
    except httpx.RequestError as exc:
        logger.error(f'[ VERIFY HTML ] {url}')
        logger.debug(exc)
        return False
        
    return True


@dataclass
class Certificate:
    """
    Certificate class to represent an X509 certificate.

    Initializes the certificate attributes by decoding a PEM certificate 
    for the given domain.
    """
    domain: str = None
    subject: str = None
    issuer: str = None
    serial_number: int = None
    not_valid_before_utc: float = None
    not_valid_after_utc: float = None
    version: int = None
    signature: str = None
    signature_hash_algorithm: str = None
    
    def __post_init__(self):
        """
        Initializes the certificate attributes by decoding a PEM certificate
        for the given domain.
        
        Decodes the PEM certificate obtained from the domain into attributes 
        like subject, issuer, validity period, etc. This allows easy access to
        certificate details after initialization.
        """
        cert = ssl.get_server_certificate(
            (self.domain, 443))
        cert_decoded = x509.load_pem_x509_certificate(
            str.encode(cert), default_backend())
        self.subject = cert_decoded.subject.rfc4514_string()
        self.issuer = cert_decoded.issuer.rfc4514_string()
        self.serial_number = cert_decoded.serial_number
        self.not_valid_before_utc = \
            cert_decoded.not_valid_before_utc.timestamp()
        self.not_valid_after_utc = \
            cert_decoded.not_valid_after_utc.timestamp()
        self.version = cert_decoded.version.value
        self.signature = cert_decoded.signature.hex()
        self.signature_hash_algorithm = \
            cert_decoded.signature_hash_algorithm.name


@dataclass
class Webpage:
    """
    Webpage class to represent a webpage and related metadata.

    Attributes include url, parent url, load time, screenshot, and child urls.
    Methods include load() to load the page in a browser and record metadata.
    """
    url: str
    domain: str = None
    path: str = None
    load_seconds: float = None
    screenshot: str = None
    urls: List[str] = None

    def __post_init__(self):
        """
        Removes edning trailing slash from the given URL.
    
        This ensures consistent formatting of URLs before further 
        processing.
        """
        self.url = remove_url_ending_slash(self.url)
        parsed_url = urlparse(self.url)
        self.domain = parsed_url.netloc
        self.path = parsed_url.path

    def load(self, browser) -> "Webpage":
        """
        Loads the webpage in the browser and records metadata.
    
        This loads the webpage at the url in the browser instance passed in.
        It records the load time, takes a screenshot, and finds child urls.
        
        Returns the Webpage instance to allow method chaining.
        """
        try:
            time_before = time.perf_counter()
            browser.get(self.url)

            time_after = time.perf_counter()
            self.load_seconds = time_after - time_before
            logger.info(f'[ {self.load_seconds:.2f} secs ] {self.url}')

        except Exception as exc:
            logger.error(f'[ LOAD WEBPAGE ] {self.url}')
            logger.debug(exc)
            return self

        self.urls = []
        for element in browser.find_elements(By.TAG_NAME, "a"):
            try:
                url = element.get_attribute("href")
                if url is None or url == "":
                    continue
                self.urls += [ url ]
            
            except StaleElementReferenceException as exc:
                logger.error(f'[ STALE ELEMENT ] {self.url}')
                logger.debug(exc)
                continue
        
        return self


@dataclass
class WebsiteOptions:
    """
    Configuration options for website mapping.

    This class contains options to control the behavior of the website 
    crawler, including whether to run headless, what URLs to skip, whether
    to take screenshots, and where to save screenshots.

    These options are set once when the mapper is initialized and apply
    to all pages mapped in that run.
    """
    do_headless: bool = True
    skip_subdomain: bool = True
    skip_upper_path: bool = True
    skip_url_args: bool = True
    skip_other_domain: bool = True
    skip_navtag: bool = True
    skip_screenshot: bool = True
    screenshot_folder: str = 'screenshots'
    screenshot_width: int = 800


@dataclass
class Website:
    """
    Website class represents a website to be crawled. It contains the root URL, 
    domain name, crawling options, and storage for crawled webpages and SSL 
    certificates discovered.

    The key methods are:

    - load() - Starts crawler threads to traverse and load webpages from the site
    - get_webpage() - Gets a loaded Webpage by URL 
    - add_webpage() - Adds a loaded Webpage
    - get_certificate() - Gets SSL Certificate by domain
    - add_certificate() - Adds discovered SSL Certificate

    The WebsiteOptions dataclass contains configuration options for the crawler.
    """
    url: str
    domain: str = field(default=None, init=False)
    path: str = field(default=None, init=False)
    options: WebsiteOptions = WebsiteOptions()
    webpages: dict = field(default_factory=dict, init=False)
    certificates: dict = field(default_factory=dict, init=False)

    def __post_init__(self):
        """
        Validate screenshot folder exists if screenshots are enabled.
        
        Raises an exception if screenshot folder does not exist but screenshots are 
        enabled in the WebsiteOptions.
        """
        self.url = remove_url_ending_slash(self.url)
        parsed_url = urlparse(self.url)
        self.domain = parsed_url.netloc
        self.path = parsed_url.path
        if not self.options.skip_screenshot:
            if not os.path.isdir(self.options.screenshot_folder):
                raise Exception(
                    f'Screenshot folder does not exist: ' + \
                    f'{self.options.screenshot_folder}'
                )

    def validate_url(self, url: str) -> bool:
        """
        Validates if a given URL matches the website's domain and mapping options.
        
        Checks if the URL matches the configured options to skip URLs with arguments, 
        navigation tags, subdomains, or other domains. This allows filtering out certain
        URLs during mapping.
        
        Returns True if the URL should be mapped based on the options, False otherwise.
        """
        if self.options.skip_url_args:
            if '?' in url:
                return False

        if self.options.skip_navtag:
            if NAVTAG in url:
                return False

        parsed_url = urlparse(url)

        if self.options.skip_other_domain:
            if not parsed_url.netloc.endswith(self.domain):
                return False

        if self.options.skip_subdomain:
            if parsed_url.netloc != self.domain:
                return False

        if self.options.skip_upper_path:
            if not parsed_url.path.startswith(self.path):
                return False

        return True

    def load(self, thread_count: int) -> None:
        """
        Loads the website by spawning multiple threads to map all pages.
        
        Spawns `thread_count` threads to map the site in parallel, with a shared 
        queue for urls and synchronization primitives to coordinate. The root url
        is added first, then threads pull urls from the queue to map until no 
        urls remain.
        """
        lock = Lock()
        break_event = Event()
        url_with_parent_queue = Queue()
        worker_queue = Queue()

        load_threads = []
        for _ in range(thread_count):
            load_thread = Thread(
                target=Website.__load_in_thread,
                args=(
                    self, lock, break_event,
                    url_with_parent_queue, worker_queue
                )
            )
            load_thread.start()
            load_threads += [ load_thread ]

        url_with_parent_queue.put_nowait((self.url, None))     
        try:
            while not break_event.is_set():
                time.sleep(10)
                if len(worker_queue.queue) == 0 \
                        and len(url_with_parent_queue.queue) == 0:
                    break_event.set()
                    logger.info("Website load complete")

        except KeyboardInterrupt:
            break_event.set()
            logger.info("KeyboardInterrupt")
        
        for load_thread in load_threads:
            load_thread.join()
    
    @staticmethod
    def __load_in_thread(
            website: "Website", lock: Lock, break_event: Event,
            url_with_parent_queue: Queue, worker_queue: Queue) -> None:
        """
        Loads webpages in a thread. 
        
        This spawns a thread that loads webpages from a queue, using a Firefox 
        browser instance. It gets urls from the queue, checks if they should be 
        skipped, loads the webpage in the browser, saves a screenshot if enabled,
        and adds child urls back to the queue. It repeats this process until the
        queue is empty.
        """
        options = FirefoxOptions()
        options.add_argument(f'--width={website.options.screenshot_width}')
        options.add_argument(f'--height={website.options.screenshot_width}')
        if website.options.do_headless:
            options.add_argument("--headless")
            logger.info('Headless mode enabled')

        with webdriver.Firefox(options=options) as browser:
            logger.info('Browser loaded')

            is_working = False
            while not break_event.is_set():
                try:
                    if is_working:
                        is_working = False
                        worker_queue.get(timeout=1)

                    (url, parent) = url_with_parent_queue.get(timeout=1)
                    is_working = True
                    worker_queue.put_nowait(is_working)

                    if not website.validate_url(url):
                        logger.debug(f'[ SKIP ] {url}')
                        continue

                    if not verify_url_as_html(url):
                        logger.debug(f'[ FILE ] {url}')
                        continue

                    with lock:
                        if website.get_webpage(url) is not None:
                            logger.debug(f'[ SKIP ] {url}')
                            continue
                        webpage = website.add_webpage(Webpage(url, parent))

                    with lock:
                        if website.get_certificate(webpage.domain) is None:
                            website.add_certificate(Certificate(webpage.domain))
                            logger.info(f'[ CERTIFICATE ] {webpage.domain}')

                    urls = webpage.load(browser).urls
                    if not website.options.skip_screenshot:
                        webpage.screenshot = save_body_screenshot(
                            browser, website.options.screenshot_folder)

                    for url in urls:
                        url = remove_url_ending_slash(url)

                        if not website.validate_url(url):
                            logger.debug(f'[ SKIP ] {url}')
                            continue

                        if webpage.url == url:
                            logger.debug(f'[ SKIP ] {url}')
                            continue

                        with lock:
                            if website.get_webpage(url) is not None:
                                logger.debug(f'[ SKIP ] {url}')
                                continue
                        
                        url_with_parent_queue.put_nowait((url, webpage.url))

                except Empty:
                    pass

                except Exception as exc:
                    logger.error(exc)
            
            browser.close()

        logger.info('Browser closed')

    def get_webpage(self, url: str) -> Webpage:
        """
        Get the Webpage object for the given URL if it exists.
        
        Parameters:
        url (str): The URL of the webpage to retrieve.
        
        Returns:
        Webpage: The Webpage object for the given URL, or None if not found.
        """
        return self.webpages.get(url)

    def add_webpage(self, webpage: Webpage) -> Webpage:
        """
        Add a Webpage object to the website.
        
        Parameters:
        webpage (Webpage): The Webpage object to add.
        
        Returns: 
        Webpage: The added Webpage object.
        """
        self.webpages[webpage.url] = webpage
        return webpage

    def get_certificate(self, domain: str) -> Certificate:
        """
        Get the Certificate object for the given domain if it exists.
        
        Parameters:
        domain (str): The domain to retrieve the certificate for.
        
        Returns:
        Certificate: The Certificate object for the given domain, or None if not found.
        """
        return self.certificates.get(domain)
    
    def add_certificate(self, certificate: Certificate) -> Certificate:
        """
        Add a Certificate object to the website.
        
        Parameters:
        certificate (Certificate): The Certificate object to add.
        
        Returns:
        Certificate: The added Certificate object. 
        """
        self.certificates[certificate.domain] = certificate
        return certificate
