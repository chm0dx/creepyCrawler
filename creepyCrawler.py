#!/usr/bin/env python3

import ast
import json
import random
import re
import requests
import sys
import threading
import time

from bs4 import BeautifulSoup, Comment
try:
    from .fireprox import fire
except ImportError:
    from fireprox import fire

from queue import Queue
from requests.packages import urllib3


class CreepyCrawler():
	def __init__(self,**kwargs):
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
		self.email = kwargs.get('email', None)
		self.headers = kwargs.get('headers', None)
		self.cookies = kwargs.get('cookies', None)
		self.proxy = kwargs.get('proxy', None)
		self.fireprox = kwargs.get('fireprox', None)
		self.robots = kwargs.get('robots', None)
		self.sitemap = kwargs.get('sitemap', None)
		self.threads = kwargs.get('threads', 10)
		self.limit = kwargs.get('limit', 500)

		self.suppress_progress = True

		self.files = []
		self.comments = False
		self.tags = False
		self.ips = False
		self.headless = False
		self.tags_list = []
		self.comments_list = []
		self.emails = []
		self.ips_list = []
		self.social_links = []
		self.cloud_storage_list = []
		self.sub_domains = []
		self.interesting = []
		self.json_endpoints = []
		self.login_pages = []
		self.processed = []
		self.alerts = []
		self.js_list = []

		self.cloud_storage_regexes = [r"([A-z0-9-]*\.s3\.amazonaws\.com)", r"[^\.](s3\.amazonaws\.com\/[A-z0-9-]*)\/", r"([A-z0-9-]*\.blob\.core\.windows\.net\/[A-z0-9-]*)", r"[^\.](storage\.googleapis\.com\/[A-z0-9-]*)\/", r"([A-z0-9-]*\.storage\.googleapis\.com)"]
		self.socials = ["youtube.com","facebook.com","instagram.com","linkedin.com","twitter.com","x.com","github.com"]
		self.socials_ignore = ["linkedin.com/feed","facebook.com/terms.php","facebook.com/privacy/explanation","linkedin.com/sharing/share-offsite/","help.github.com","linkedin.com/redir","facebook.com/dialog","linkedin.com/feed/hashtag","linkedin.com/cws","twitter.com/hashtag","x.com/hashtag","facebook.com/sharer","twitter.com/intent","twitter.com/home?status=","x.com/intent","x.com/home?status=","facebook.com/sharer.php","facebook.com/share.php","linkedin.com/shareArticle","youtube.com/ads","youtube.com/about","youtube.com/creators","youtube.com/howyoutubeworks","google.com/youtube","twitter.com/share","twitter.com/privacy","x.com/share","x.com/privacy","linkedin.com/static","linkedin.com/learning","help.instagram.com","facebook.com/policy.php","facebook.com/help","facebook.com/about","facebook.com/ads","developers.facebook.com"]
		self.file_extensions = [".pdf",".docx",".doc",".xlsx",".xls",".pptx",".ppt",".exe",".zip",".7z",".7zip","pkg","deb"]
		self.media_files_ignore = [".png",".gif",".jpg"]
		self.file_content_types = ["application/pdf"]
		self.interesting_content_types = []
		self.cf_strings = ["Checking if the site connection is secure","Attention Required!", "Just a moment..."]
		self.tag_filters = [r"\b(UA-[\d-]{3,})", r"\b(AW-[\d-]{3,})", r"\b(G-(?=.{6,})(?:\d+[a-zA-Z]|[a-zA-Z]+\d)[a-zA-Z\d-]+)", r"\b(GTM-[\w]{3,})"]
		self.fp_requests = []
		self.fp_urls = {}
		self.queue = Queue()
		self.done = threading.Event()
		self.__dict__.update(kwargs)
		self.base_domain = ".".join(self.url.split("/")[-1].split(".")[-2:])
		self.email_domains = self.email or self.base_domain
		self.email_domains = self.email_domains.split(",")

		if self.headers:
			self.headers = ast.literal_eval(self.headers)
		else:
			self.headers = {'user-agent':'Screaming Frog SEO Spider/6.2'}
		if self.cookies:
			self.cookies = ast.literal_eval(self.cookies)
		else:
			self.cookies = {}
		if self.proxy:
			self.proxy = {"http":self.proxy,"https":self.proxy}
		if "https://" not in self.url and "http://" not in self.url:
			self.url = f"http://{self.url}"
		if self.fireprox:
			self.fp = fire.FireProx(
				region=self.region,
				access_key=self.access_key,
				secret_access_key=self.secret_access_key
			)
			random_url = '.'.join(str(random.randint(0,255)) for _ in range(4))
			self.headers["X-My-X-Forwarded-For"] = random_url
			self.fp_done = threading.Event()
			threading.Thread(target=self.manage_fp,args=(),daemon=True).start()


	def manage_fp(self):
		while not self.done.is_set():
			while self.fp_requests:
				requested_url = self.fp_requests.pop()
				if not self.fp_urls.get(requested_url):
					if not self.suppress_progress:
						print(f"Creating FireProx endpoint for {requested_url}...")
					fp_url = re.search(r"=> (.*) ", self.fp.create_api(requested_url))[1]
					self.fp_urls[requested_url] = fp_url
		if not self.suppress_progress:
				print(f"Cleaning up FireProx endpoints...")
		fp_ids = list(self.fp_urls.values())
		while fp_ids:
			fp_id = fp_ids.pop().replace("https://","").split(".")[0]
			try:
				self.fp.delete_api(fp_id)
			except:
				time.sleep(.1)
				fp_ids.append(fp_id)
		self.fp_done.set()


	def prepare_fireprox_url(self,url):
		base_url = "/".join(url.split("/")[0:3])
		path = "/".join(url.split("/")[3:])
		if path.endswith("/"):
			path = path[:-1] + "%2F"
		if not self.fp_urls.get(base_url):
			self.fp_requests.append(base_url)
		while not self.fp_urls.get(base_url):
			time.sleep(1)
		fp_url = self.fp_urls.get(base_url)
		fp_id = fp_url.replace("https://","").split(".")[0]
		url = f"{fp_url}{path}"
		return url, fp_id


	def precheck_url(self,url):
		base_url = url.split("?")[0].split("#")[0]
		if url.endswith("email-protection"):
			return
		if "mailto" in url:
			return
		if any(base_url.endswith(extension) for extension in self.media_files_ignore):
			return
		if re.findall(fr"[^A-z-]({'|'.join(self.socials)})\/",base_url) and not any(ignore in base_url for ignore in self.socials_ignore):

		#if any(social in base_url for social in self.socials) and not any(ignore in base_url for ignore in self.socials_ignore):
			if url.count("/") < 3:
				return
			self.social_links.append(url.split("#")[0])
			return
		if any(base_url.endswith(extension) for extension in self.file_extensions):
			self.files.append(url.split("#")[0])
			return
		return True


	def postcheck_url(self,url):
		url_domain = url.replace("https://","").replace("http://","").split("/")[0]
		if url_domain.endswith(self.base_domain):
			if url_domain is not self.base_domain and url_domain not in self.sub_domains:
				self.sub_domains.append(url_domain)
			if url not in self.processed and url not in self.queue.queue:
				return True
		return


	def url_from_link(self, link, current_url):
		base_url = "/".join(current_url.split("/")[0:3])
		protocol = base_url.split("/")[0]
		if "@" in link:
			return
		if link.startswith("../"):
			count = link.count("../")
			link = f'{"/".join(current_url.split("/")[:-1*count])}/{link.replace("../","")}'
		if link.startswith("//"):
			link = link.replace("//","")
		elif link.startswith("/"):
			link = f"{base_url}{link}"
		if "//" in link and not link.startswith("http"):
			return
		if ":" in link and not link.startswith("http"):
			return
		if "http://" not in link and "https://" not in link:
			if "." not in link.split("/")[0]:
				link = f"{base_url}/{link}"
			else:
				link = f"{base_url}/{link}"
				#link = f"{protocol}//{link}"
		return link


	def precheck_response(self, response):
		if response.status_code == 500:
			return
		if response.status_code == 429:
			if not self.alerts:
				self.alerts.append("Server responded with 429 'Too Many Requests'. Wait a bit and back off threads.")
			return
		elif response.status_code == 403:
			if response.headers.get("CF-RAY") and any(cf_string in response.text for cf_string in self.cf_strings):
				if not self.alerts:
					self.alerts.append("Cloudflare challenge detected.")
				return
		return True


	def crawler(self):
		while True:
			url = self.queue.get()
			if url is None:
				self.queue.task_done()
				continue
			if self.alerts:
				self.queue.task_done()
				continue
			if self.limit != 0 and len(self.processed) > self.limit:
				self.alerts.append("Stopped when the link processing limit was reached")
				self.queue.task_done()
				continue
			try:
				if not self.suppress_progress:
					print("Crawling {}".format(url.replace("%2F","/")))
				
				self.processed.append(url)
				original_url = url
				original_base_url = "/".join(original_url.split("/")[0:3])
				original_protocol = original_base_url.split("/")[0]
				if self.fireprox:
					url, fp_id = self.prepare_fireprox_url(url)
					
				response = requests.get(url, headers=self.headers, cookies=self.cookies, proxies=self.proxy, verify=False, stream=True, timeout=10, allow_redirects=False)
				if not self.precheck_response(response):
					self.queue.task_done()
					response.close()
					continue
				if response.is_redirect:
					next_url = response.next.url
					if self.fireprox and fp_id in next_url:
						next_path = "/".join(next_url.split("/")[3:]).replace("fireprox/","")
						next_url = f"{original_base_url}/{next_path}"
					if self.postcheck_url(next_url):
						self.queue.put(next_url)
					self.queue.task_done()
					response.close()
					continue
				current_url = response.url
				if self.fireprox and fp_id in current_url:
					current_url = original_url
				
				if response.headers.get("Content-Security-Policy") and "frame-ancestors" in response.headers.get("Content-Security-Policy").lower():
					self.interesting.append(response.headers.get("Content-Security-Policy"))
					sub_matches = re.findall(rf'[A-z-]+\.{self.base_domain}',response.headers.get("Content-Security-Policy"))
					if sub_matches:
						print(response.headers.get("Content-Security-Policy"))
					self.sub_domains.extend(sub_matches)
				if response.headers.get("content-type") and "text/html" not in response.headers.get("content-type"):
					if any(response.url.endswith(extension) for extension in self.file_extensions):
						self.files.append(current_url.split("#")[0])
					elif any(response.headers.get("content-type") == content_type for content_type in self.file_content_types):
						self.files.append(current_url.split("#")[0])
					elif any(response.headers.get("content-type") == content_type for content_type in self.interesting_content_types):
						self.interesting.append(current_url)
					elif response.headers.get("content-type") == "application/json":
						self.json_endpoints.append(current_url)
						
					self.queue.task_done()
					response.close()
					continue
				
				if current_url != original_url and current_url in self.processed:
					self.queue.task_done()
					response.close()
					continue			

				if not self.precheck_url(current_url):
					self.queue.task_done()
					response.close()
					continue
				
				if self.headless:
					from playwright.sync_api import sync_playwright

					with sync_playwright() as p:
						browser = p.chromium.launch(headless=True)
						context = browser.new_context(extra_http_headers=self.headers)
						if self.cookies:
							domain = re.findall(r'([a-zA-Z0-9\-]*\.[a-zA-Z0-9]*)',url)[0]
							headless_cookies = [{"name":name,"value":value,"path":"/", "domain":domain} for name,value in self.cookies.items()]
							context.add_cookies(headless_cookies)
						page = context.new_page()
						page.goto(url)
						response_text = page.content()
				else:
					response_text = response.text
					
				response.close()
				soup = BeautifulSoup(response_text,"lxml")

				if self.js:
					script_srcs = [script for script in soup.select("script") if script.get("src")]
					for script in script_srcs:
						if script.get("src").startswith("/"):
							self.js_list.append(original_base_url + script.get("src"))
						elif original_base_url in script.get("src"):
							self.js_list.append(script.get("src"))

				if soup.select('[type="password"]'):
					self.login_pages.append(current_url)

				for cloud_storage_regex in self.cloud_storage_regexes:
					self.cloud_storage_list.extend(re.findall(rf'{cloud_storage_regex}',response_text))

				if self.ips:
					self.ips_list.extend(re.findall(r'[^0-9-a-zA-Z]((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2}))[^0-9-a-zA-Z]',response.text))
	
				for email_domain in self.email_domains:
					self.emails.extend([email.lower() for email in re.findall(fr"((?<!\\)[A-Za-z0-9+.]+@[\w]*{email_domain})", response_text)])

				if self.comments:
					self.comments_list.extend([comment.strip() for comment in soup.find_all(string=lambda text:isinstance(text, Comment))])

				if self.tags:
					for filter in self.tag_filters:
						self.tags_list.extend([tag.strip().lower() for tag in re.findall(filter,response_text)])
						if "g-suite" in self.tags_list:
							a = 1

				hrefs = list(set([a["href"] for a in soup.find_all("a",href=True)]))
				if not hrefs:
					if "Incapsula incident ID" in response_text:
						if not self.alerts:
							self.alerts.append(f"Incapsula challenge detected.")
					self.queue.task_done()
					continue

				for href in hrefs:
					href = self.url_from_link(href,current_url)
					if href and self.precheck_url(href):
						href = href.split("#")[0].split("?")[0].lower().strip()
						if href and self.postcheck_url(href):
							self.queue.put(href)
						
			except requests.exceptions.TooManyRedirects:
				pass
			except requests.exceptions.Timeout:
				pass
			except requests.exceptions.ConnectionError:
				pass
			except Exception as ex:
				self.alerts.append(f"Unhandled exception ({str(ex)})")

			self.queue.task_done()


	def process_robots(self,url):
		original_url = url
		original_base_url = "/".join(original_url.split("/")[0:3])
		base_url = original_base_url
		original_protocol = original_base_url.split("/")[0]
		if not url.endswith("/"):
			url = url + "/"
		url = url + "robots.txt"
		if self.fireprox:
			url,fp_id = self.prepare_fireprox_url(url)
		response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=False, stream=True, timeout=10, allow_redirects=False)
		if not self.precheck_response(response):
			return
		redirect_count = 0
		while response.is_redirect:
			response.close()
			redirect_count += 1
			if redirect_count > 5:
				return False
			url = response.next.url
			base_url = "/".join(url.split("/")[0:3])
			if self.fireprox:
				url,fp_id = self.prepare_fireprox_url(url)
			response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=False, stream=True, timeout=10, allow_redirects=False)
			if not self.precheck_response(response):
				response.close()
				return
		
		robots_urls = []
		self.sitemaps = []
		for line in response.text.splitlines():
			if self.robots:
				if "allow:" in line.lower():
					resource = line.replace("Disallow:","").replace("Allow:","").replace("*","").strip()
					if resource != "/?":
						if resource and resource != "/?":
							url = f"{base_url}{resource}"
							if url not in robots_urls and self.postcheck_url(url):
								self.queue.put(url)
								robots_urls.append(url)
			if self.sitemap and "Sitemap:" in line:
					self.sitemaps.append(line.replace("Sitemap:","").strip())
		response.close()
		if self.sitemap:
			if not self.sitemaps:
				self.sitemaps.append(f"{base_url}/sitemap.xml")


	def process_sitemap(self,url):
		original_url = url
		original_base_url = "/".join(original_url.split("/")[0:3])
		base_url = original_base_url
		original_protocol = original_base_url.split("/")[0]
		if self.fireprox:
			url,fp_id = self.prepare_fireprox_url(url)
		response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=False, stream=True, timeout=10, allow_redirects=False)
		if not self.precheck_response(response):
			response.close()
			return
		redirect_count = 0
		while response.is_redirect:
			response.close()
			redirect_count += 1
			if redirect_count > 5:
				return False
			url = response.next.url
			base_url = "/".join(url.split("/")[0:3])
			if self.fireprox:
				url,fp_id = self.prepare_fireprox_url(url)
			response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=False, stream=True, timeout=10, allow_redirects=False)
			if not self.precheck_response(response):
				response.close()
				return
		soup = BeautifulSoup(response.text,"xml")
		response.close()
		if soup.find("sitemapindex"):
			for url in soup.find_all("loc"):
				self.sitemaps.append(url.text)
		else:
			for url in soup.find_all("loc"):
				if self.postcheck_url(url.text):
					self.queue.put(url.text)


	def watcher(self):
		self.queue.join()
		self.done.set()


	def crawl(self):
		if self.robots or self.sitemap:
			if not self.suppress_progress:
				if self.robots:
					print("Processing robots.txt...")
				else:
					print("Processing sitemap...")
			self.process_robots(self.url)

			if self.sitemap:
				if not self.suppress_progress:
					if self.robots:
						print("Processing sitemap...")
				for url in self.sitemaps:
					self.process_sitemap(url)

		if not self.suppress_progress:
			print("Preparing to crawl...")
		self.queue.put(self.url)
		crawlers = [threading.Thread(target=self.crawler,args=(),daemon=True) for _ in range(self.threads)]
		[crawler.start() for crawler in crawlers]
		threading.Thread(target=self.watcher,args=(),daemon=True).start()
		
		try:
			self.done.wait()
		except KeyboardInterrupt:
			if not self.suppress_progress:
				print("\nTerminating...")
			self.alerts.append("Terminated early due to keyboard interrupt")
		if self.fireprox:
			self.fp_done.wait()

		return {
			"urls":list(set(self.processed)),
			"sub_domains":list(set(self.sub_domains)),
			"social_links":list(set(self.social_links)),
			"emails":list(set(self.emails)),
			"cloud_storages":list(set(self.cloud_storage_list)),
			"ips":list(set(self.ips_list)),
			"files":list(set(self.files)),
			"interesting":list(set(self.interesting)),
			"comments":list(set(self.comments_list)),
			"tags":list(set(self.tags_list)),
			"alerts":list(set(self.alerts)),
			"json_endpoints":list(set(self.json_endpoints)),
			"login_pages":list(set(self.login_pages)),
			"js_list":list(set(self.js_list))
		}


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description = "Crawl a site and extract useful recon info.")
	parser.add_argument(
		"--url",
		required=True,
		help="An initial URL to target."
	)
	parser.add_argument(
		"--email",
		required=False,
		help="A comma-separated list of email domains to look for in page content. Defaults to the root domain of the passed-in URL."
	)
	parser.add_argument(
		"--threads",
		required=False,
		help="The max number of threads to use. Defaults to 10.",
		default=10,
		type=int
	)
	parser.add_argument(
		"--limit",
		required=False,
		help="The number of URLs to process before exiting. Defaults to 500. Set to 0 for no limit (careful).",
		default=500,
		type=int
	)
	parser.add_argument(
		"--proxy",
		required=False,
		help="Specify a proxy to use."
	)
	parser.add_argument(
		"--headers",
		required=False,
		help="Override defaults with the indicated headers. ex: \"{'user-agent':'value','accept':'value'}\""
	)
	parser.add_argument(
		"--cookies",
		required=False,
		help="Provide cookies to use in requests. Useful for auth. ex: \"{'Authorization':'value','blah':'value'}\""
	)
	parser.add_argument(
		"--fireprox",
		required=False,
		help="Automatically configure FireProx endpoints as needed. Pass in credentials or use the ~/.aws/credentials file.",
		action="store_true"
	)
	parser.add_argument(
		"--region",
		required=False,
		help="The AWS region to create FireProx resources in."
	)
	parser.add_argument(
		"--access_key",
		required=False,
		help="The access key used to create FireProx resources in AWS."
	)
	parser.add_argument(
		"--secret_access_key",
		required=False,
		help="The secret access key used to create FireProx resources in AWS."
	)
	parser.add_argument(
		"--json",
		required=False,
		help="Output in JSON format",
		action="store_true"
	)
	parser.add_argument(
		"--headless",
		required=False,
		help="Run in headless mode. Requires Playwright and deps (or use docker).",
		action="store_true"
	)
	parser.add_argument(
		"--robots",
		required=False,
		help="Search pages found in the robots.txt file",
		action="store_true"
	)
	parser.add_argument(
		"--sitemap",
		required=False,
		help="Search pages found in the site's sitemap",
		action="store_true"
	)
	parser.add_argument(
		"--suppress_progress",
		required=False,
		help="Only show final output",
		action="store_true"
	)
	parser.add_argument(
		"--comments",
		required=False,
		help="Return HTML comments extracted from crawled pages",
		action="store_true"
	)
	parser.add_argument(
		"--tags",
		required=False,
		help="Return tags (UA,GTM,etc.) extracted from crawled pages",
		action="store_true"
	)
	parser.add_argument(
		"--ips",
		required=False,
		help="Return IP addresses extracted from crawled page content",
		action="store_true"
	)
	parser.add_argument(
		"--js",
		required=False,
		help="Return a list of local JS sources from crawled content",
		action="store_true"
	)
	args = parser.parse_args()
	if not args.access_key and args.secret_access_key:
		sys.exit("When providing keys, provide both an access key and a secret access key.")

	try:
		creepycrawler = CreepyCrawler(**vars(args))
		results = creepycrawler.crawl()
	except Exception as ex:
		sys.exit(ex)
	if args.json:
		print(json.dumps(results))
	else:
		if results.get("social_links"):
			socials = dict(zip([link.lower() for link in results.get("social_links")], results.get("social_links"))).values()
			print(f"\nSocial Links ({len(results.get('social_links'))}):")
			for social_link in sorted(list(set(socials))):
				print(f"\t{social_link}")
		if results.get("sub_domains"):
			print(f"\nSubdomains ({len(results.get('sub_domains'))}):")
			for sub_domain in results.get("sub_domains"):
				print(f"\t{sub_domain}")
		if results.get("emails"):
			print(f"\nEmails ({len(results.get('emails'))}):")
			for email in results.get("emails"):
				print(f"\t{email}")
		if results.get("files"):
			print(f"\nFiles ({len(results.get('files'))}):")
			for file in sorted(results.get("files")):
				print(f"\t{file}")
		if results.get("cloud_storages"):
			print(f"\nCloud Storage ({len(results.get('cloud_storages'))}):")
			for cloud_storage in sorted(results.get("cloud_storages")):
				print(f"\t{cloud_storage}")
		if results.get("login_pages"):
			print(f"\nLogin Pages ({len(results.get('login_pages'))}):")
			for login_page in sorted(results.get("login_pages")):
				print(f"\t{login_page}")
		if results.get("ips"):
			print(f"\nIPs ({len(results.get('ips'))}):")
			for ip in sorted(results.get("ips")):
				print(f"\t{ip}")
		if results.get("json_endpoints"):
			print(f"\nJSON Endpoints ({len(results.get('json_endpoints'))}):")
			for item in results.get("json_endpoints"):
				print(f"\t{item}")
		if results.get("interesting"):
			print(f"\nInteresting ({len(results.get('interesting'))}):")
			for item in results.get("interesting"):
				print(f"\t{item}")
		if results.get("comments"):
			print(f"\nComments ({len(results.get('comments'))}):")
			for item in results.get("comments"):
				print(f"\t{item}")
		if results.get("tags"):
			print(f"\nTags ({len(results.get('tags'))}):")
			for item in results.get("tags"):
				print(f"\t{item}")
		if results.get("js_list"):
			print(f"\nJS Sources ({len(results.get('js_list'))}):")
			for item in results.get("js_list"):
				print(f"\t{item}")
		for alert in results.get("alerts"):
			print(f"\nALERT:\t{alert}")

		print(f"\nFinished processing {len(creepycrawler.processed)} URLs")
