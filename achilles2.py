#!/usr/bin/env python3

import argparse
import validators
import requests
import yaml
from bs4 import BeautifulSoup
from bs4 import Comment
from urllib.parse import urlparse

parser = argparse.ArgumentParser(description='CSUK Achilles - A HTML Vulnerability Analyser v1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s v1.0')
parser.add_argument('url', type=str, help="Enter URL to analyse")
parser.add_argument('--config', help='Path to config file')
parser.add_argument('--output', help='Path to Report file')

args = parser.parse_args()

config = {'forms': True, 'comments': True, 'passwords': True}
config_default = "Default Config"

if args.config:
    config_file = open(args.config, 'r')
    conf_from_file = yaml.load(config_file, Loader=yaml.SafeLoader)
    if conf_from_file:
        config = {**config, **conf_from_file}
        config_default = args.config

report = ''
url = args.url

if validators.url(url):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    forms = parsed_html.find_all('form')
    comments = parsed_html.find_all(string=lambda text: isinstance(text, Comment))
    password_inputs = parsed_html.find_all('input', {'name': 'password'})

    print("\n==========================================")
    print("   CSUK Achilles > Starting Checks...   ")
    print("==========================================\n")

    check_all = True
    check_form = False
    check_comm = False
    check_pass = False

    if config['forms']:
        print(' << Checking Forms >> \n')
        check_form = True
        for form in forms:
            if (form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https'):
                report += '[+] CSUK HTML Analyser << Forms are not secure >> \n' + form.get('action') + ' found\n'

    if config['comments']:
        print(' << Checking Comments >> \n')
        check_comm = True
        for comment in comments:
            if comment.find('key') > -1:
                report += '\n[+] CSUK HTML Analyser << Possible Key Found >>\n' + str(comment.find('key')) + ' found\n'

    if config['passwords']:
        print(' << Checking Inputs >> \n')
        check_pass = True
        for password_input in password_inputs:
            if password_input.get('type') != 'password':
                report += '\n[+] CSUK HTML Analyser << Issue with Input >>\n' + 'Plain text for password found in type ' \
                                                                                'input\n '

    if not check_form:
        if not check_comm:
            if not check_pass:
                check_all = False
                print(' << !! No Checks Performed !! >> \n')
                report += '!! Config - No Checks Performed: ' + str(config) + '\n'

else:
    print("[-] Invalid URL > use http://www.your-url.com\n")

header = ('============================================\n')
header += ("   CSUK Achilles > HTML Analyser Report   \n")
header += ('============================================\n\n')
header += ("URL: " + url + "\nConfig: " + config_default + "\n")
header += ("Check All: " + str(check_all) + "\n\n")

if report == '':
    approved = ("[+] CSUK HTML Analyser << Website OK >>\n")
    report = header + approved
else:
    report = header + report
    print(report)

if args.output:
    f = open(args.output, 'w')
    f.write(report)
    f.close()
    print('============================================')
    print("       Report Saved >> " + args.output)
    print('============================================\n')
