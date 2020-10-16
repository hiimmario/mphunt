# mphunt
utility for reading and processing mitmdump dumpfiles

mitmdump comes with mitmproxy (https://mitmproxy.org/) which is required to run this script (https://pypi.org/project/mitmproxy/).

the script checks parameter names of so called flows (req/response pairs) against a list of names (issue.json - from jason haddix) and filters them accordingly.
it also creates a not so useful report, but its primarly the base for further automatization.

### inspired and based on Jason Haddixs HUNT Burp Plugin Research @Jhaddix
https://github.com/bugcrowd/HUNT
