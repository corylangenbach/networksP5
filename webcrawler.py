#!/usr/bin/env python

import socket
import ssl
import re
from bs4 import BeautifulSoup





HTTP_VER = "HTTP/1.1"
# HTTP_VER = "HTTP/1.0"

HOST = "fakebook.3700.network"
visted_pages = set()

COOKIE = ''

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
            request_fields =    f'Connection: {self.connection}\r\n'\
                                f'Host: {self.host}\r\n'\
                                'Upgrade-Insecure-Requests: 1\r\n'\
                                'Origin: https://fakebook.3700.network\r\n'\
                                'Content-Type: application/x-www-form-urlencoded\r\n'\
                                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n'\
                                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'\
                                'Referer: https://fakebook.3700.network/accounts/login/\r\n'\
                                'Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n'\
                                f'Cookie: {self.cookie}'
        elif self.method == GET:
            request_fields =    f'Connection: {self.connection}\r\n'\
                                f'Host: {self.host}\r\n'\
                                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"\
                                f'Cookie: {self.cookie}'
        request_fields += "\r\n\r\n"
        return method_line + request_fields 

GET = 'GET'
POST = 'POST'

def format_get_request(path, cookie=''):
    # res = REQ_HEADER.format(method=GET, path=path, http_ver=HTTP_VER, host=HOST, cookie=cookie)
    get_req = RequestHeader(GET, path, cookie=cookie)
    return get_req.format_request()
def format_post_request(path, cookie, username, password, csrfmiddlewaretoken):
    # post_header = REQ_HEADER.format(method=POST,path=path, http_ver=HTTP_VER, host=HOST, cookie=cookie)
    post_header = RequestHeader(POST, path, cookie=cookie)
    post_body = f"username={username}&password={password}&csrfmiddlewaretoken={csrfmiddlewaretoken}&next="
    # post_body = "username=nzukie.b&password=UX7S0C5ZVG1H3UPK&csrfmiddlewaretoken=8a8JWn50Kd6HpfL4tPCVBJwAICbmiyA6abQMzJ3UOHXHGKipvPPGuZ4cLOxnCTDi&next="
    return post_header.format_request() + post_body
def get_cookie(soup):
    """Returns the cookie provided by Set-Cookie"""
    token = re.search(r'csrftoken=.*', str(soup))
    if token:
        COOKIE = re.split(r'\r\n', token.group())[0].strip().split(';')[0]
        # print(repr(COOKIE))
        return COOKIE
    

def connect():
    hostname = "fakebook.3700.network"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, 443))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    s = context.wrap_socket(s, server_hostname=hostname)
    return s


def initial_get(s):
    get_request = format_get_request('/')
    print(get_request)
    # get_request = "GET / HTTP/1.1\r\nHost: fakebook.3700.network\r\n\r\n"
    s.sendall(get_request.encode())
    data_back = s.recv(4096)
    soup = BeautifulSoup(data_back, 'html.parser')
    for anchor in soup.find_all('a'):
        if "Log in" in anchor.string:
            login = anchor.get("href")
            break
    get_cookie(soup)
    return s, login, COOKIE

def login_get(s, login, cookie):
    login_req = format_get_request(login, cookie)
    print(login_req)
    s.sendall(login_req.encode())
    data_back_login = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_login, 'html.parser')
    print(soup_recv)
    csrfmiddlewaretoken = None
    for each in soup_recv.find_all("input"):
        if each.get("name") == "csrfmiddlewaretoken":
            csrfmiddlewaretoken = each.get("value")
    cookie = get_cookie(soup_recv)
    print(cookie, csrfmiddlewaretoken)
    return s, soup_recv, cookie, csrfmiddlewaretoken

def send_creds(s, login, cookie, middleware_token):
    # TODO: get username and password from cmd line
    username = "nzukie.b"
    password = "UX7S0C5ZVG1H3UPK"
    post_request = format_post_request(login, cookie, username, password, middleware_token)
    print(repr(post_request))
    s.sendall(post_request.encode())
    data_back_post = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_post, 'html.parser')
    return s, soup_recv

    # # clean up cookie
    # #print(cookie)
    # #just_value = cookie[len(cookie)::]

    # post ="""POST /accounts/login/ HTTP/1.1\r\n
    # "Host: fakebook.3700.network\r\n
    # Connection: keep-alive\r\n
    # Content-Length: 148\r\n
    # Cache-Control: max-age=0\r\n
    # sec-ch-ua: "Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"\r\n
    # sec-ch-ua-mobile: ?0\r\n
    # sec-ch-ua-platform: "Windows"\r\n
    # Upgrade-Insecure-Requests: 1\r\n
    # Origin: https://fakebook.3700.network\r\n
    # Content-Type: application/x-www-form-urlencoded\r\n
    # User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n
    # Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n
    # cp-extension-installed: Yes\r\n
    # Sec-Fetch-Site: same-origin\r\n
    # Sec-Fetch-Mode: navigate\r\n
    # Sec-Fetch-User: ?1\r\n
    # Sec-Fetch-Dest: document\r\n
    # Referer: https://fakebook.3700.network/accounts/login/?next=/fakebook/\r\n
    # Accept-Encoding: gzip, deflate, br\r\n
    # Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n
    # Cookie: """ + cookie + """\r\n\r\n
    # id_username=langenbach.c&id_password=CT90K8S2P4WDPFLU&next=%2Ffakebook%2F\r\n"""

    # post2 = """POST /accounts/login/ HTTP/1.1\r\n
    # Host: fakebook.3700.network\r\n
    # Connection: keep-alive\r\n
    # Content-Length: 134\r\n
    # Origin: https://fakebook.3700.network\r\n
    # Content-Type: application/x-www-form-urlencoded\r\n
    # User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n
    # Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n
    # Referer: https://fakebook.3700.network/accounts/login/?next=/fakebook/\r\n
    # Cookie: """ + cookie + """\r\n\r\n
    # username=langenbach.c&password=CT90K8S2P4WDPFLU&csrfmiddlewaretoken=""" + csrfmiddlewaretoken + """&next=%2Ffakebook%2F\r\n"""



def crawl():
    # connect to fakebook
    s = connect()
    # send get to root, get login link
    s, login, cookie = initial_get(s)
    # send get to login link
    s, login_recv, cookie, csrfmiddlewaretoken = login_get(s, login, cookie)
    s, msg_back = send_creds(s, login, cookie, csrfmiddlewaretoken)
    print(msg_back)

    #print("logged in", msg_back.head)
    #print("loggined in", msg_back)





if __name__ == "__main__":
    crawl()


