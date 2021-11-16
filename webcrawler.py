#!/usr/bin/env python

import socket
import ssl
import re
import argparse
from bs4 import BeautifulSoup


HTTP_VER = "HTTP/1.1"
# HTTP_VER = "HTTP/1.0"
HOST = "fakebook.3700.network"
VISITED_PAGES = set()
COOKIE = ''
SESSION_ID = ''
GET = 'GET'
POST = 'POST'
FOUND_FLAGS = set()

parser = argparse.ArgumentParser()
parser.add_argument('username', action='store', type=str, help='username for webcrawler login')
parser.add_argument('password', action='store', type=str, help='password for webcrawler login')

class RequestHeader:
    def __init__(self, method, path, cookie=None, session_id=None):
        self.method = method
        self.path = path
        self.http_ver = HTTP_VER
        self.host = HOST
        self.connection = 'keep-alive'
        self.content_length = None
        self.content_type = None
        self.cookie = cookie
        self.session_id = session_id

    def format_request(self):
        method_line = f'{self.method} {self.path} {self.http_ver}\r\n'
        request_fields =    f'Host: {self.host}\r\n'\
                            f'Connection: {self.connection}\r\n'\
                            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"\
                            'Upgrade-Insecure-Requests: 1\r\n'\
                            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n' \
                            f'Cookie: {self.cookie};{self.session_id}\r\n'\
                            'Accept-Language: en-US,en;q=0.9,fr;q=0.8'

        if self.method == POST:
            # NOTE: Content-length should be number of chars in body e.g. len(username=...&password=...&etc)
            request_fields += '\r\nOrigin: https://fakebook.3700.network\r\n'\
                f'Content-Length: {self.content_length}\r\n'\
                'Content-Type: application/x-www-form-urlencoded\r\n'\
                f'Cookie: {self.cookie};{self.session_id}'
        request_fields += "\r\n\r\n"
        return method_line + request_fields


def format_get_request(path):
    get_req = RequestHeader(GET, path, cookie=COOKIE, session_id=SESSION_ID)
    return get_req.format_request()

def format_post_request(path, username, password, csrfmiddlewaretoken):
    post_header = RequestHeader(POST, path, cookie=COOKIE)
    post_body = f"username={username}&password={password}&csrfmiddlewaretoken={csrfmiddlewaretoken}&next=\r\n\r\n"
    post_header.content_length = len(post_body)
    return post_header.format_request() + post_body

def get_cookie(soup):
    """Handles updating Cookie and sessionid with values provided from set-cookie"""
    global COOKIE, SESSION_ID
    cookie = re.search(r'csrftoken=.*', str(soup))
    session_id = re.search(r'sessionid=.*', str(soup))
    if cookie:
        COOKIE = cookie.group().strip().split(';')[0]
    if session_id:
        SESSION_ID = session_id.group().strip().split(';')[0]

def connect():
    hostname = "fakebook.3700.network"
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

def send_creds(s, login, username, password, middleware_token):
    post_request = format_post_request(login, username, password, middleware_token)
    # print(post_request)
    s.sendall(post_request.encode())
    data_back_post = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_post, 'html.parser')
    return soup_recv

def login(username, password):
    # connect to fakebook
    s = connect()
    # send get to root, get login link
    login = initial_get(s)
    # send get to login link
    login_recv, csrfmiddlewaretoken = login_page_get(s, login)
    login_response = send_creds(s, login, username, password, csrfmiddlewaretoken)
    #  Update cookies adn session_id
    get_cookie(login_response)
    # print(login_response)
    if COOKIE and SESSION_ID:
        print(f'Login Successful.\n{COOKIE}\n{SESSION_ID}')
        VISITED_PAGES.add(login)
        return s
    return None

def validate_response(response, s, path):
    correct_data_back = response
    # if get 302 error
    if str(response)[9:12] == "302":
        new_url = response.search(r'Location:.*', str(response))
        new_url = new_url.split('\r\n')[0]
        new_url = new_url[9::]
        s.sendall(new_url.encode())
        data_back = s.recv(8192)
        correct_data_back = BeautifulSoup(data_back, 'html.parser')
    # if get 403/404 error
    if str(response)[9:12] == "403" or str(response)[9:12] == "404":
        correct_data_back = None
    # if get 500 error
    if str(response)[9:12] == "500":
        while str(response)[9:12] == "500":
            new_request = format_get_request(path)
            s.sendall(new_request.encode())
            data = s.recv(8192)
            response = BeautifulSoup(data, 'html.parser')
            continue
        correct_data_back = response

    return correct_data_back, s

def crawl(username, password):
    #global VISITED_PAGES

    s = login(username, password)
    links_to_visit = []
    # add logout page so we don't accidentally logout
    VISITED_PAGES.add("/accounts/logout/")

    if s:
        root_request = format_get_request("/")
        VISITED_PAGES.add("/")
        s.sendall(root_request.encode())
        data_back_login = s.recv(8192)
        soup_recv = BeautifulSoup(data_back_login, 'html.parser')
        soup_recv, s = validate_response(soup_recv, s, '/')
        if not soup_recv:
            raise Exception("GOT BAD DATA ON ROOT REQUEST, ABANDONING")
        get_cookie(soup_recv)

        for anchor in soup_recv.find_all('a'):
            if anchor.get("href") not in VISITED_PAGES and anchor.get("href")[0:1] == "/":
                links_to_visit.append(anchor.get("href"))

        while len(links_to_visit) > 0:
            # pop the last element off list, search it, put it in visited list
            path = links_to_visit.pop()
            print("sending get request", path)
            if path not in VISITED_PAGES:
                VISITED_PAGES.add(path)
                new_request = format_get_request(path)
                s.sendall(new_request.encode())
                data = s.recv(8192)
                data_pretty = BeautifulSoup(data, 'html.parser')
                data_pretty, s = validate_response(data_pretty, s, path)
                if data_pretty:
                    get_cookie(data_pretty)
                    # add new found links if not already visited and valid
                    #print("found page", data_pretty)
                    for anchor in data_pretty.find_all('a'):
                        if anchor.get("href") not in VISITED_PAGES and anchor.get("href")[0:1] == "/":
                            print("adding to search list", anchor)
                            links_to_visit.append(anchor.get("href"))
                    # check for secret flags
                    flag = data_pretty.find("h2", {"class": "secret_flag"})
                    if flag:
                        print("found a flag!")
                        FOUND_FLAGS.add(flag.getText())
                        if len(FOUND_FLAGS) == 5:
                            break
                else:
                    VISITED_PAGES.add(path)
        print("flags: ", FOUND_FLAGS)


if __name__ == "__main__":
    args = parser.parse_args()
    username, password = args.username, args.password
    if not username or not password:
        username = "nzukie.b"
        password = "UX7S0C5ZVG1H3UPK"
    crawl(username, password)
