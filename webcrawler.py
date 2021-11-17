#!/usr/bin/env python
import sys
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
PAGES_TO_VIST = set()

f = open('log.txt', 'w')
sys.stdout = f

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
                            'Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n'\
                            f'Cookie: {self.cookie}; {self.session_id}'\

        if self.method == POST:
            # NOTE: Content-length should be number of chars in body e.g. len(username=...&password=...&etc)
            request_fields += '\r\nOrigin: https://fakebook.3700.network\r\n'\
                f'Content-Length: {self.content_length}\r\n'\
                'Content-Type: application/x-www-form-urlencoded'
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

def send_get_request(sock, path):
    """Sends a get request to the provide path updates cookies and secret_flag if present in response"""
    request = format_get_request(path)
    print(f'SENDING: {request}')
    while True:
        try:
            sock.sendall(request.encode())
            data = sock.recv(8192)
            soup = BeautifulSoup(data, 'html.parser')
            get_cookie(soup)
            search_for_flag(soup)
            break
        except ssl.SSLZeroReturnError as e:
            print(f'ERROR SOCKET CLOSED: {e}. REOPENING')
            sock = connect()
    return soup, sock


def get_cookie(soup):
    """Handles updating Cookie and sessionid with values provided from set-cookie"""
    global COOKIE, SESSION_ID
    cookie = re.search(r'csrftoken=.*', str(soup))
    session_id = re.search(r'sessionid=.*', str(soup))
    if cookie:
        COOKIE = cookie.group().strip().split(';')[0]
    if session_id:
        SESSION_ID = session_id.group().strip().split(';')[0]

def search_for_flag(soup):
    global FOUND_FLAGS
    flag = soup.find("h2", {"class": "secret_flag"})
    if flag:
        FOUND_FLAGS.add(flag.text)
        print(f'FLAG: {flag}, {FOUND_FLAGS}')
    
def get_links_on_page(soup):
    """Returns a set of links to the other pages of the site from the provided page"""
    links_on_page = set()
    for anchor in soup.find_all('a'):
        path = anchor.get('href')
        # print(path, path.startswith('/'))
        if path not in VISITED_PAGES and path.startswith('/'):
            links_on_page.add(path)
    return links_on_page


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
    login = '/login'
    for anchor in soup.find_all('a'):
        if "Log in" in anchor.string:
            login = anchor.get("href")
            break
    get_cookie(soup)
    return login

def login_page_get(s, login):
    soup_recv, s = send_get_request(s, login)
    csrfmiddlewaretoken = soup_recv.find("input", {"name": "csrfmiddlewaretoken"})["value"]
    # print(COOKIE, csrfmiddlewaretoken)
    return soup_recv, csrfmiddlewaretoken

def send_creds(s, login, username, password, middleware_token):
    post_request = format_post_request(login, username, password, middleware_token)
    # print(post_request)
    s.sendall(post_request.encode())
    data_back_post = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_post, 'html.parser')
    return soup_recv

def login(s, username, password):
    global VISITED_PAGES
    # connect to fakebook
    # send get to root, get login link
    login = initial_get(s)
    # send get to login link
    login_recv, csrfmiddlewaretoken = login_page_get(s, login)
    login_response = send_creds(s, login, username, password, csrfmiddlewaretoken)
    #  Update cookies adn session_id
    get_cookie(login_response)
    response = validate_response(login_response, s, login)
    # print(login_response)
    if COOKIE and SESSION_ID:
        print(f'Login Successful.\n{COOKIE}\n{SESSION_ID}')
        VISITED_PAGES.add(login)
        return response
    return None

def validate_response(response, s, path):
    global VISITED_PAGES
    # correct_data_back = response
    response_code = str(response)[9:12].strip()
    print(f'VALIDATING: {response_code}')
    if not response_code:
        print('NO RESPONSE', response)
    # if get 302 error
    if response_code == "302":
        print(f'302 response: {response}')
        new_url = re.search(r'Location:.*', str(response))
        print(f'NEW URL: {new_url}')
        new_url = new_url.group()[9::].strip()
        # print(new_url)
        # print(f'new_url: {new_url}')
        # new_url = new_url[9::]
        print(f'NEW URL: {new_url}')
        soup_recv, s = send_get_request(s, new_url)
        response = validate_response(soup_recv, s, new_url)
        print(f'302 response resolved: {response}')
        VISITED_PAGES.add(new_url)
    # if get 403/404 error
    if response_code == "403" or response_code == "404":
        correct_data_back = None
    # if get 500 error
    if response_code == "500":
        print(f'500 response: {response}')
        soup_recv, s = send_get_request(s, path)
        response = validate_response(soup_recv, s, path)
        print(f'500 response resolved: {response}')
    
    correct_data_back = response
    return correct_data_back

def crawl(username, password):
    global FOUND_FLAGS
    s = connect()
    #global VISITED_PAGES
    #Navigate to login page and send post request
    soup_recv = login(s, username, password)
    print(f'LOGIN: {soup_recv}')
    links_to_search = set()
    # add logout page so we don't accidentally logout
    VISITED_PAGES.add("/accounts/logout/")
    VISITED_PAGES.add("/accounts/login/")
    VISITED_PAGES.add("[]")
    if soup_recv:
        search_for_flag(soup_recv)
        new_links = get_links_on_page(soup_recv)
        print(f'new_links1: {new_links}')
        print(f'VISITED_PAGES1: {VISITED_PAGES}')
        links_to_search.update(new_links)
        print(f'LINKS_TO_SEARCH1: {links_to_search}')
        while links_to_search:
            links_seen = set()
            # BFS
            for path in links_to_search:
                if path not in VISITED_PAGES:
                    print(f'CHECKING PATH: {path}')
                    soup_recv, s = send_get_request(s, path)
                    soup_recv = validate_response(soup_recv, s, path)
                    if soup_recv:
                        new_links = get_links_on_page(soup_recv)
                        links_seen.update(new_links)
                    VISITED_PAGES.add(path)
                    if len(FOUND_FLAGS) == 5:
                        links_seen.clear()
                        links_to_search.clear()
                        break
            # All previously found links have been searched
            links_to_search.clear()
            # Update links_to_search with new found links
            links_to_search.update(links_seen)
            continue
    print(f'FINAL: {FOUND_FLAGS}')

if __name__ == "__main__":
    args = parser.parse_args()
    username, password = args.username, args.password
    if not username or not password:
        username = "nzukie.b"
        password = "UX7S0C5ZVG1H3UPK"
    crawl(username, password)
