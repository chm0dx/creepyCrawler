# creepyCrawler

OSINT tool to crawl a site and extract useful recon info.

 * Provide a starting URL and automatically gather URLs to crawl via hrefs, robots.txt, and sitemap 
 * Extract useful recon info:
    * Emails
    * Social media links
    * Subdomains
    * Files
    * A list of crawled site links
    * HTML comments
    * Marketing tags (UA,GTM, etc.)
    * 'Interesting' findings such as frame ancestors content and resource that return JSON content
 * Built-in FireProx to automatically create endpoints for each subdomain, rotate source IP, and cleanup at the end
    * Forked and modified ([chm0dx/fireprox](https://github.com/chm0dx/fireprox)) from the awesome [ustayready/fireprox](https://github.com/ustayready/fireprox)
 * HTTP/SOCKS proxy support
 
 ![alt text](./creepyCrawler_demo.gif "Quick Demo")

## Install

    git clone https://github.com/chm0dx/creepyCrawler.git
    cd creepyCrawler
    pip install -r requirements.txt

## Use

    creepyCrawler.py --url URL [--email EMAIL] [--threads THREADS] [--limit LIMIT] [--proxy PROXY] [--headers HEADERS] [--fireprox]
                     [--region REGION] [--access_key ACCESS_KEY] [--secret_access_key SECRET_ACCESS_KEY] [--json] [--robots]
                     [--sitemap] [--suppress_progress] [--comments] [--tags]

    Crawl a site and extract useful recon info.

    optional arguments:
      -h, --help            show this help message and exit
      --url URL             An initial URL to target.
      --email EMAIL         A comma-separated list of email domains to look for. Defaults to the root domain of the passed-in URL.
      --threads THREADS     The max number of threads to use. Defaults to 10.
      --limit LIMIT         The number of URLs to process before exiting. Defaults to 500. Set to 0 for no limit (careful).
      --proxy PROXY         Specify a proxy to use.
      --headers HEADERS     Override defaults with the indicated headers. ex: "{'user-agent':'value','accept':'value'}"
      --fireprox            Automatically configure FireProx endpoints. Pass in credentials or use the ~/.aws/credentials file.
      --region REGION       The AWS region to create FireProx resources in.
      --access_key ACCESS_KEY
                            The access key used to create FireProx resources in AWS.
      --secret_access_key SECRET_ACCESS_KEY
                            The secret access key used to create FireProx resources in AWS.
      --json                Output in JSON format
      --robots              Search pages found in the robots.txt file
      --sitemap             Search pages found in the site's sitemap
      --suppress_progress   Only show final output
      --comments            Return HTML comments extracted from crawled pages
      --tags                Return tags (UA,GTM,etc.) extracted from crawled pages


![I bet you can hear the song in your head...](https://media.giphy.com/media/Lz1LMB0rTWhNIKZdmD/giphy.gif)
