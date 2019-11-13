#!/usr/bin/python

import requests
import optparse
import re


parser = optparse.OptionParser()
parser.add_option("-w", "--wordlist", dest="wordlist", help="Wordlist file location(full path)")
(options,arguments) = parser.parse_args() 


url = open(options.wordlist,"r")

### Test if a website use HSTS ###
print('\x1b[1;37;44m'+'[*]'+'\x1b[0m'+' Testing for HSTS existence...')
for line in url:
	urlS = line.strip()
	r = requests.get(urlS, verify=True)
	if "strict-transport-security" in r.headers:
		print('\x1b[1;37;42m'+'[+]'+'\x1b[0m'+' '+urlS+' '+'\x1b[1;37;42m'+'is using HSTS!'+'\x1b[0m') 
	else:
		
		print('\x1b[1;37;41m'+'[-]'+'\x1b[0m'+' '+urlS+' '+'\x1b[1;37;41m'+'is not using HSTS!'+'\x1b[0m')




url = open(options.wordlist,"r")

### Test if a website use XSS Protection ###
print('\x1b[1;37;44m'+'[*]'+'\x1b[0m'+' Testing for XSS Protection...')
for line in url:
        urlS = line.strip()
        r = requests.get(urlS, verify=True)
        if "X-XSS-Protection" in r.headers:
                print('\x1b[1;37;42m'+'[+]'+'\x1b[0m'+' '+urlS+' '+'\x1b[1;37;42m'+'is using XSS Protection!'+'\x1b[0m') 
        else:
                
                print('\x1b[1;37;41m'+'[-]'+'\x1b[0m'+' '+urlS+' '+'\x1b[1;37;41m'+'is not using XSS Protection!'+'\x1b[0m')


url = open(options.wordlist,"r")

### Test if a website use Clickjacking Protection ###
print('\x1b[1;37;44m'+'[*]'+'\x1b[0m'+' Testing for Clickjack protection...')
for line in url:
        urlS = line.strip()
        r = requests.get(urlS, verify=True)
        if "X-Frame-Options" in r.headers:
                print('\x1b[1;37;42m'+'[+]'+'\x1b[0m'+' '+urlS+' '+'\x1b[1;37;42m'+'is protected against Clickjacking!'+'\x1b[0m') 
        else:
                
                print('\x1b[1;37;41m'+'[-]'+'\x1b[0m'+' '+urlS+' '+'\x1b[1;37;41m'+'is not not protected against Clickjacking!'+'\x1b[0m')



url = open(options.wordlist,"r")

### Extract JS with source (libraries) ###
print('\x1b[1;37;44m'+'[*]'+'\x1b[0m'+' Extracting JavaScript libraries...')
for line in url:
        urlS = line.strip()
        r = requests.get(urlS)
        scripts = re.findall('<script[^>]+src="([^">]+)"', r.content)
        for script in scripts:
            if "main.js" and not "main.js" in script:
                print('\x1b[1;37;43m'+'[+]'+'\x1b[0m'+' '+urlS+" is using "'\x1b[1;37;43m'+str(script)+'\x1b[0m'+" JavaScript library")
