![Logo of the project](https://raw.githubusercontent.com/rtm-python/ii/master/ii.png)

# IssueInspector (ii)

> A simple tool to monitor services (resources) to detect issues (or problems) with availability of services (resources)

IssueInspector (ii) provides 'agent' package, which functionality accessible from CLI and could be imported to other projects.

## Getting started

### Install virtual environment
It should be pre-installed Python version 3.7 or higher.
```shell
python -m venv <path_to_virtual_environment>
```

### Activate virtual environment and install requirements
For GNU/Linux users
```shell
. venv/bin/activate
```
or for Windows users
```shell
venv\Scripts\activate
```
After activation you should see (venv_name) in your command line, then install requirements.
```shell
(venv_name) pip install -r requirements.txt 
```

### Run package from CLI
To dicover all arguments run the following command
```shell
(venv_name) python agent --help
usage: agent [-h] [--debug] [--do-headless] [--skip-subdomains] [--skip-upper-paths] [--skip-url-args] [--skip-other-domains] [--skip-navtags]
             [--skip-screenshots] [--screenshot-width SCREENSHOT_WIDTH] [--thread-count THREAD_COUNT] [--url URL] [--search-text SEARCH_TEXT]
             [--output-folder OUTPUT_FOLDER]

optional arguments:
  -h, --help            show this help message and exit
  --debug
  --do-headless
  --skip-subdomains
  --skip-upper-paths
  --skip-url-args
  --skip-other-domains
  --skip-navtags
  --skip-screenshots
  --screenshot-width SCREENSHOT_WIDTH
  --thread-count THREAD_COUNT
  --url URL
  --search-text SEARCH_TEXT
  --output-folder OUTPUT_FOLDER
```
Or run without any arguments, which will run the default configuration on https://www.python.org as shown below.
```shell
(venv_name) python agent
2024-03-01 21:26:43,555 | AGENT:INFO | debug = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | do_headless = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | skip_subdomains = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | skip_upper_paths = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | skip_url_args = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | skip_other_domains = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | skip_navtags = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | skip_screenshots = False | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | screenshot_width = 1024 | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | thread_count = 10 | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | url = https://www.python.org/ | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | search_text = None | __main__:<module>:38
2024-03-01 21:26:43,555 | AGENT:INFO | output_folder = None | __main__:<module>:38
2024-03-01 21:27:03,407 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:03,821 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:05,413 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:05,813 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:05,870 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:06,436 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:06,505 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:07,058 | AGENT:INFO | [ CERTIFICATE ] www.python.org | mapper:__load_in_thread:453
2024-03-01 21:27:07,458 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:27:07,916 | AGENT:INFO | Browser loaded | mapper:__load_in_thread:423
2024-03-01 21:28:13,198 | AGENT:INFO | [ 66.14 secs ] https://www.python.org | mapper:load:197
...
```