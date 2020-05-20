#!/usr/bin/env python3
# import sys

# print('The first argument was: ' + sys.argv[1]) #argv[0] = file name
# print(sys.argv)

import argparse
import validators 
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description = 'The Achilles HTML Vulnerability Analyzer Version 1.0')

parser.add_argument('-v', '--version', action = 'version', version = '%(prog)s 1.0')
parser.add_argument('url', type = str, help = 'The URL of the HTML to analyze')
parser.add_argument('-c', '--config', help = 'Path to configuration file')
parser.add_argument('-o', '--output', help = 'Report file output path')

args = parser.parse_args()

# print(args)
# print(args.url)

config = {'forms': True, 'comments': True, 'passwords': True}

if(args.config):
    print('Using config file: ' + args.config)
    config_file = open(args.config, 'r')
    config_from_file = yaml.safe_load(config_file)
    if(config_from_file):
        # config = config_from_file
        config = {**config, **config_from_file}
    # print(config)
    
report = ''

url = args.url

if (validators.url(url)):
    # print('That was a good URL')
    result_html = requests.get(url).text
    # print(result_html)
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    # print(parsed_html.title)

    forms           = parsed_html.find_all('form')
    # print(parsed_html.find_all('h1'))
    comments        = parsed_html.find_all(string = lambda text:isinstance(text, Comment))
    password_inputs = parsed_html.find_all('input', {'name' : 'password'})

    if(config['forms']):
        for form in forms:
            if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
                # form_is_secure = False
                # print(form_is_secure)
                report += 'Form Issue: Insecure form action ' + form.get('action') + ' found in document\n'
    if(config['comments']):
        for comment in comments:
            if(comment.find('key: ') > -1):
                report += 'Comment Issue: Key is found in the HTML comments, please remove\n'
    if(config['passwords']):
        for password in password_inputs:
            if(password.find('type') != 'password'):
                report += 'Input Issue: PlainText password input found. Please change to password type input\n'

else:
    # print('That one wasn\'t so good')
    print('Invalid URL. Please include full URL including scheme.')

if(report == ''):
    report += 'Nice Job! Your HTML document is secure!'
else:
    header = 'Vulnerability Report is as follows: \n'
    header += '====================================\n\n'
    report = header + report
# print(report)

if(args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print('Report saved to: ' + args.output)