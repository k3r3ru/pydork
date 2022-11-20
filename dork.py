import sys
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from fake_useragent import UserAgent
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import time
from random import randint
from socket import *
import re
from requests import Session
from bs4 import BeautifulSoup
import argparse
import telnetlib


parser = argparse.ArgumentParser(description="Domain to scan")
parser.add_argument("domain", type=str, help="domain to scan")
parser.add_argument("--urlenum", dest="urlenum", action="store_true", help="check waybackmachine for sensitive urls", required=False)
args = parser.parse_args()


firefox_options = Options()
ua = UserAgent(verify_ssl=False)
userAgent = ua.random
firefox_options.add_argument("--headless")
firefox_options.add_argument(f"user-agent={userAgent}")
firefox_options.add_argument("--window-size=1920x1080")
firefox_options.set_preference("intl.accept_languages", "en-GB")
driver = webdriver.Firefox(options=firefox_options)


def googleSearch(domain):
    driver.get("https://www.google.com/")
    driver.find_element(By.CSS_SELECTOR, "#L2AGLb > div").click()
    time.sleep(0.5)
    sbox = driver.find_element(By.NAME, "q")
    sbox.send_keys("site:" + domain)
    time.sleep(randint(1, 2))
    sbox.send_keys(Keys.ENTER)
    time.sleep(randint(1, 2))
    dorkedDoms = []

    pageNum = 0
    while(True):
        pageNum += 1
        try:
            span = WebDriverWait(driver, 5).until(expected_conditions.presence_of_element_located((By.XPATH, "//span[text()='Next']")))
        except:
            break
        print(f"Fetching Google Page #{pageNum}")
        time.sleep(randint(1, 2))
        driver.find_element(By.XPATH, "//span[text()='Next']").click()
        for dom in fetchDoms(domain):
            dorkedDoms.append(dom)

    driver.close()
    driver.quit()
    deduplist = list(set(dorkedDoms))

    retList = []
    if not deduplist:
        for dom in deduplist:
            sans = sanScan(dom)
            for san in sans:
                retList.append(san)
    retList += deduplist
    retList = list(set(retList))
    return retList


def fetchDoms(domain):
    domlist = []
    elems = driver.find_elements(By.XPATH, "//a[@href]")
    for elem in elems:
        href = elem.get_attribute("href")
        splitHref = href.split("/")
        for token in splitHref:
            if token.endswith(domain):
                domlist.append(token)
    return domlist


def checkOpenPort(domain):
    try:
        telnetlib.Telnet(domain, 443)
    except:
        return False
    return True


def sanScan(url):
    sans = []
    if checkOpenPort(url):

        httpRemove = re.compile(r"https?://")
        fqdn = re.sub(httpRemove, "", url)
        setdefaulttimeout(5)

        try:
            pem = ssl.get_server_certificate((fqdn, 443))
        except (error):
            print(f"SSL ERROR - {url}")
            return

        pemBytes = bytes(pem, 'utf-8')
        cert = x509.load_pem_x509_certificate(pemBytes, default_backend())

        for ext in cert.extensions:
            ext = ext.value
            if isinstance(ext, x509.SubjectAlternativeName):
                sans = ext.get_values_for_type(x509.DNSName)

    else:
        print(f"Port 443 appears to be closed on host {url} - Can't fetch x509 SANs list")
    return sans


def fetchUrls(domain):
    urlList = []

    try:
        s = Session()
        html = s.get(f"https://web.archive.org/web/timemap/json?url={domain}&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&filter=!statuscode%3A%5B45%5D..&limit=10000&_=1661714575377")
        bs = BeautifulSoup(html.text, "html.parser")
        res = str(bs).replace("[", "").replace("]", "").split(",")
        s.close()
        for token in res:
            if domain in token: urlList.append(token.strip().replace('"', ""))
        return urlList
    except:
        print(f"Connection error on url enumeration for: {domain}")
    return urlList


def checkSensitiveInfo(list):
    f = open("sensitive", "r")
    lines = f.readlines()
    for url in list:
        for l in lines:
            stripPath = l.strip("\n")
            if stripPath != "":
                if re.search(f"/{stripPath}/", url) and not (url.endswith(".png") or url.endswith(".jpg") or url.endswith(".svg") or url.endswith(".ttf") or url.endswith(".eot") or url.endswith(".gif")):
                    print(f"FOUND: {stripPath} in {url}")


doms = googleSearch(args.domain)
print("\nFOUND FOLLOWING DOMAINS:\n")
outdoms = open("subs.txt", "x")

for d in doms:
    print(d)
    outdoms.write(d)

if args.urlenum:
    for d in doms:
        print(f"SCANNING DOMAIN: {d}")
        checkSensitiveInfo(fetchUrls(d))