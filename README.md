# pydork
A simple Python script to find publicly indexed subdomains of a given domain through Selenium web browser automation. The TLS certificate SAN field is checked for additional domains, if available on port 443.

Optionally, the script can fetch known urls for each domain and check them against a wordlist of notoriously sensitive web server folders.

----------------------------------------------------------------------------------------------

USAGE: dork.py [-h] [--urlenum] domain

--urlenum optionally checks for known sensitive urls associated with each domain discovered

----------------------------------------------------------------------------------------------

TODO:

* Add multithreading support to speed up the optional url enumeration
* Test different wordlists
* Add support for other search engines
