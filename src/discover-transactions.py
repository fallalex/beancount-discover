#!/usr/bin/env python3
from __future__ import print_function
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import base64
from pprint import pprint
import re
import time
import requests
import sys
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from den import bwHelper
from pprint import pprint

# https://github.com/mozilla/geckodriver/releases/download/v0.29.0/geckodriver-v0.29.0-macos.tar.gz
# https://developers.google.com/gmail/api/quickstart/python
# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
# https://console.developers.google.com/?authuser=1

# with requests.Session() as s:
    # s.headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0'}
    # transations_req = s.get('https://card.discover.com/cardmembersvcs/statements/app/stmt.download?date=all24&sortColumn=trans_date&grouping=-1&printView=false&sortOrder=Y&transaction=-1&printOption=transactions&way=actvt&includePend=Y&outputFormat=csv')

class discover_client():
    def __init__(self, gmail):
        self.gmail = gmail
        # self.driver = webdriver.Firefox(executable_path='./geckodriver')
        self.driver = webdriver.Chrome(executable_path='./chromedriver')
        self.wait = WebDriverWait(self.driver, 10)
        self.login_url = 'https://www.discover.com'
        self.code_request_url = 'https://card.discover.com/cardmembersvcs/strongauth/app/sa_main'
        self.code_entry_url = 'https://card.discover.com/cardmembersvcs/strongauth/app/oobRequest'
        self.login_success_url = 'https://portal.discover.com/customersvcs/portal/summary'
        self.login_user_field = 'userid-content'
        self.login_pass_field = 'password-content'
        self.delay = 1 # seconds
        self.code_poll_interval = 10 # seconds
        self.code_poll_timeout = 65 # seconds
        self.username, self.password = get_credential()
        self.email_radio_xpath = '//input[@type="radio" and @value="EMAIL0"]'
        self.code_field = 'codeEntry'

        # self.driver.quit()

    def login(self):
        self.driver.get(self.login_url)
        try:
           user_field = WebDriverWait(self.driver, self.delay).until(EC.presence_of_element_located((By.ID, self.login_user_field)))
        except TimeoutException:
            print("Page wait timed out looking for element with id '{}'".format(self.login_user_field))
            return
        user_field.send_keys(self.username)
        pass_field = self.driver.find_element_by_id(self.login_pass_field)
        pass_field.send_keys(self.password)
        pass_field.submit()

        # https://www.selenium.dev/selenium/docs/api/py/webdriver_support/selenium.webdriver.support.expected_conditions.html
        # selenium.webdriver.support.expected_conditions.any_of(*expected_conditions)
        # TODO: The following does not work as I'd like should wait for specific urls and rely on timeout
        self.wait.until(lambda driver: driver.current_url != self.login_url)

        if self.driver.current_url == self.code_request_url:
            self.request_code()
        if self.driver.current_url == self.login_success_url:
            print('Login Successful')
            return True
        else:
            print('Login Failed')
            return False

    # TODO: unsure how codes are handled
    # are they truely one use?
    # is it state ware? ie if a code has not be used that was sent will it not send a new one unless requested?
    # TODO: consider deleting the email after login is confirmed
    # TODO: would like to know how to ensure I am proped for a code ever login while testing
    def request_code(self):
        try:
           email_radio = WebDriverWait(self.driver, self.delay).until(EC.presence_of_element_located((By.XPATH, self.email_radio_xpath)))
        except TimeoutException:
            print("Page wait timed out looking for element with id '{}'".format(self.email_radio_xpath))
            return
        email_radio.click()
        email_radio.submit()
        self.wait.until(lambda driver: driver.current_url != self.code_request_url)
        if self.driver.current_url == self.code_entry_url:
            self.poll_code()
        else:
            print(self.driver.current_url, 'expected', self.code_entry_url)

    def poll_code(self):
        request_time = int(time.time())
        while (int(time.time()) - request_time) <= self.code_poll_timeout:
            time.sleep(self.code_poll_interval)
            self.code = self.gmail.get_code(request_time)
            if self.code == None: continue
            self.submit_code()
            self.wait.until(lambda driver: driver.current_url != self.code_entry_url)

    def submit_code(self):
        try:
           code_field = WebDriverWait(self.driver, self.delay).until(EC.presence_of_element_located((By.ID, self.code_field)))
        except TimeoutException:
            print("Page wait timed out looking for element with id '{}'".format(self.code_field))
            return
        code_field.sendkeys(self.code)
        code_field.submit()


class gmail_client():
    def __init__(self):
        self.filter = 'from:discover@service.discover.com in:finances subject:Code'
        # If modifying these scopes, delete the file token.json.
        self.scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.client_secret = 'credentials.json'
        self.client_token = 'token.json'
        self.charset = 'iso-8859-1'
        self.mime_type = 'text/plain'
        # self.mime_type = 'text/html'

        self.charset_re = re.compile('charset="(.*)"', flags=re.IGNORECASE)
        self.code_re = re.compile('code: (\d+)', flags=re.IGNORECASE)

        self.authenticate_client()

    def authenticate_client(self):
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists(self.client_token):
            creds = Credentials.from_authorized_user_file(self.client_token, self.scopes)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.client_secret, self.scopes)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(self.client_token, 'w') as token:
                token.write(creds.to_json())
        self.service = build('gmail', 'v1', credentials=creds)

    def get_charset(self, headers):
        for h in headers:
            if h['name'].lower() == 'content-type':
                matches = self.charset_re.findall(h['value'])
                if len(matches) == 1:
                    self.charset = matches[0]

    def get_code(self, later_than):
        result = self.service.users().messages().list(
            q=self.filter,
            userId='me', maxResults=1).execute()
        messages = result.get('messages', [])
        if len(messages) != 1:
            print('{} emails found with filter {} expected 1'.format(len(messages), self.filter))
            return None
        msg = self.service.users().messages().get(userId='me', id=messages[0]['id']).execute()
        s, _ = divmod(int(msg['internalDate']), 1000)
        print('Received {} seconds ago'.format(int(time.time())-s))
        if s - later_than < 0:
            print('Email from {} is older that cut-off of {}'.format(s, later_than))
            return None
        try:
            # pprint(msg)
            for p in msg['payload'].get('parts'):
                if p['mimeType'].lower() == self.mime_type:
                    self.get_charset(p['headers'])
                    base64_body = base64.b64decode(p['body']['data'].encode("UTF-8"))
                    body = base64_body.decode(self.charset)
                    # print(body)
                    matches = self.code_re.findall(body)
                    if len(matches) == 1:
                        return matches[0]
                    print('Found {} matches in email body'.format(len(matches)))
        except Exception as e:
            print(e)
        return None

def get_credential():
    bw = bwHelper()
    bw.decrypt_cache()
    cred_id = bw.item_id('discover', 'No Folder')
    cred = bw.get_item(cred_id)
    return (cred['login']['username'], cred['login']['password'])

# login
gmail = gmail_client()
discover = discover_client(gmail)
discover.login()
# gmail.get_code(int(time.time()))
# gmail.get_code(1616303891)

# copy cookies to requests session
# download transactions via resquests

# def main():
#     pass

# if __name__ == '__main__':
#     main()
