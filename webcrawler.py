#!/usr/bin/env python

import socket
import ssl
import re
import argparse
from bs4 import BeautifulSoup


HTTP_VER = "HTTP/1.1"
# HTTP_VER = "HTTP/1.0"

HOST = "fakebook.3700.network"
visted_pages = set()

COOKIE = ''
SESSION_ID = ''

class RequestHeader:
    def __init__(self, method, path, cookie=None):
        self.method = method
        self.path = path
        self.http_ver = HTTP_VER
        self.host = HOST
        self.connection = 'keep-alive'
        self.content_length = None
        self.content_type = None
        self.cookie = cookie

    def format_request(self):
        method_line = f'{self.method} {self.path} {self.http_ver}\r\n'
        if self.method == POST:
            # TODO Content-Length should be
            request_fields = f'Host: {self.host}\r\n'\
                f'Connection: {self.connection}\r\n'\
                'Upgrade-Insecure-Requests: 1\r\n'\
                'Origin: https://fakebook.3700.network\r\n'\
                f'Content-Length: {self.content_length}\r\n'\
                'Content-Type: application/x-www-form-urlencoded\r\n'\
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n'\
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'\
                'Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n'\
                f'Cookie: {self.cookie}'
        elif self.method == GET:
            request_fields = f'Host: {self.host}\r\n'\
                f'Connection: {self.connection}\r\n'\
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"\
                "DNT: 1\r\n"\
                'Upgrade-Insecure-Requests: 1\r\n'\
                f'Cookie: {self.cookie}'
        request_fields += "\r\n\r\n"
        return method_line + request_fields


GET = 'GET'
POST = 'POST'


def format_get_request(path):
    get_req = RequestHeader(GET, path, cookie=COOKIE)
    return get_req.format_request()

def format_post_request(path, username, password, csrfmiddlewaretoken):
    post_header = RequestHeader(POST, path, cookie=COOKIE)
    post_body = f"username={username}&password={password}&csrfmiddlewaretoken={csrfmiddlewaretoken}&next=\r\n\r\n"
    post_header.content_length = len(post_body)
    return post_header.format_request() + post_body

def get_cookie(soup):
    """Handles updating Cookie and sessionid with values provided from set-cookie"""
    global COOKIE, SESSION_ID
    token = re.search(r'csrftoken=.*', str(soup))
    if token:
        temp = re.split(r'\r\n', token.group())[0].strip().split(';')
        COOKIE = temp[0]
        session_id = re.search(r'sessionid=.*', str(soup))
        if session_id:
            SESSION_ID = session_id.group().strip().split(';')[0]
        return COOKIE

def connect():
    hostname = "fakebook.3700.network"
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = socket.create_connection((hostname, 443))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    s = context.wrap_socket(s, server_hostname=hostname)
    return s

def initial_get(s):
    get_request = format_get_request('/')
    # print(get_request)
    s.sendall(get_request.encode())
    data_back = s.recv(4096)
    soup = BeautifulSoup(data_back, 'html.parser')
    for anchor in soup.find_all('a'):
        if "Log in" in anchor.string:
            login = anchor.get("href")
            break
    get_cookie(soup)
    return login

def login_page_get(s, login):
    login_req = format_get_request(login)
    # print(login_req)
    s.sendall(login_req.encode())
    data_back_login = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_login, 'html.parser')
    csrfmiddlewaretoken = soup_recv.find("input", {"name": "csrfmiddlewaretoken"})["value"]
    get_cookie(soup_recv)
    # print(COOKIE, csrfmiddlewaretoken)
    return soup_recv, csrfmiddlewaretoken

def send_creds(s, login, middleware_token):
    # TODO: get username and password from cmd line
    username = "nzukie.b"
    password = "UX7S0C5ZVG1H3UPK"
    post_request = format_post_request(login, username, password, middleware_token)
    # print(post_request)
    s.sendall(post_request.encode())
    data_back_post = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_post, 'html.parser')
    return soup_recv


def login():
    # connect to fakebook
    s = connect()
    # send get to root, get login link
    login = initial_get(s)
    # send get to login link
    login_recv, csrfmiddlewaretoken = login_page_get(s, login)
    login_response = send_creds(s, login, csrfmiddlewaretoken)
    #  Update cookies with provided sessionid
    get_cookie(login_response)
    print(COOKIE)
    print(SESSION_ID)
    # print(login_response)

def crawl():
    login()
    #print("logged in", msg_back.head)
    #print("loggined in", msg_back)

if __name__ == "__main__":
    crawl()
