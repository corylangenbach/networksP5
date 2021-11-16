#!/usr/bin/env python

import socket
import ssl
from bs4 import BeautifulSoup


def connect():
    hostname = "fakebook.3700.network"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, 443))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    s = context.wrap_socket(s, server_hostname=hostname)
    return s


def initial_get(s):
    get_request = "GET / HTTP/1.1\r\nHost: fakebook.3700.network\r\n\r\n"
    s.sendall(get_request.encode())
    data_back = s.recv(4096)
    soup = BeautifulSoup(data_back, 'html.parser')
    login = None
    for anchor in soup.find_all('a'):
        if "Log in" in anchor.string:
            login = anchor.get("href")
            break
    return s, login

def login_get(s, login):
    get_request_login = "GET " + login + " HTTP/1.1\r\nHost: fakebook.3700.network\r\n\r\n"
    s.sendall(get_request_login.encode())
    data_back_login = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_login, 'html.parser')

    csrfmiddlewaretoken = None
    for each in soup_recv.find_all("input"):
        if each.get("name") == "csrfmiddlewaretoken":
            csrfmiddlewaretoken = each.get("value")

    start_index = (str(soup_recv).index("Set-Cookie"))
    temp_string = str(soup_recv)[str(soup_recv).index("Set-Cookie") + 1:]

    cookie_temp = temp_string.split()[1]
    cookie = cookie_temp[0:len(cookie_temp)-1]
    return s, soup_recv, cookie, csrfmiddlewaretoken

def send_creds(s, login, cookie, csrfmiddlewaretoken):
    # TODO: get username and password from cmd line

    # clean up cookie
    #print(cookie)
    #just_value = cookie[len(cookie)::]

    post ="""POST /accounts/login/ HTTP/1.1\r\n
    "Host: fakebook.3700.network\r\n
    Connection: keep-alive\r\n
    Content-Length: 148\r\n
    Cache-Control: max-age=0\r\n
    sec-ch-ua: "Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"\r\n
    sec-ch-ua-mobile: ?0\r\n
    sec-ch-ua-platform: "Windows"\r\n
    Upgrade-Insecure-Requests: 1\r\n
    Origin: https://fakebook.3700.network\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n
    cp-extension-installed: Yes\r\n
    Sec-Fetch-Site: same-origin\r\n
    Sec-Fetch-Mode: navigate\r\n
    Sec-Fetch-User: ?1\r\n
    Sec-Fetch-Dest: document\r\n
    Referer: https://fakebook.3700.network/accounts/login/?next=/fakebook/\r\n
    Accept-Encoding: gzip, deflate, br\r\n
    Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n
    Cookie: """ + cookie + """\r\n\r\n
    id_username=langenbach.c&id_password=CT90K8S2P4WDPFLU&next=%2Ffakebook%2F\r\n"""

    post2 = """POST /accounts/login/ HTTP/1.1\r\n
    Host: fakebook.3700.network\r\n
    Connection: keep-alive\r\n
    Content-Length: 134\r\n
    Origin: https://fakebook.3700.network\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n
    Referer: https://fakebook.3700.network/accounts/login/?next=/fakebook/\r\n
    Cookie: """ + cookie + """\r\n\r\n
    username=langenbach.c&password=CT90K8S2P4WDPFLU&csrfmiddlewaretoken=""" + csrfmiddlewaretoken + """&next=%2Ffakebook%2F\r\n"""

    post3 = """Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n
    Accept-Encoding: gzip, deflate, br\r\n
    Accept-Language: en-US,en;q=0.9\r\n
    Cache-Control: max-age=0\r\n
    Connection: keep-alive\r\n
    Content-Length: 138\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    Cookie: csrftoken=QxwiHPaBt6C6sT8a8qptwsJucMdIWih7KzCcB7zEmIcsK4Tvx4Gn7E8LsSivFsQC\r\n
    Host: fakebook.5700.network\r\n
    Origin: https://fakebook.5700.network\r\n
    Referer: https://fakebook.5700.network/accounts/login/\r\n
    sec-ch-ua: "Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"\r\n
    sec-ch-ua-mobile: ?1\r\n
    sec-ch-ua-platform: "Android"\r\n
    Sec-Fetch-Dest: document\r\n
    Sec-Fetch-Mode: navigate\r\n
    Sec-Fetch-Site: same-origin\r\n
    Sec-Fetch-User: ?1\r\n
    Upgrade-Insecure-Requests: 1\r\n
    User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Mobile Safari/537.36\r\n\r\n
    username=langenbach.c&password=CT90K8S2P4WDPFLU&csrfmiddlewaretoken=jPQloo0lSHE3CeX9D0IATo1qYpHQ59QldRWfiGpoLjepUpIu2EZuuAqHevMDOjpQ"""

    post_request = post2
    s.sendall(post_request.encode())
    data_back_post = s.recv(4096)
    soup_recv = BeautifulSoup(data_back_post, 'html.parser')
    return s, soup_recv


def crawl():
    # connect to fakebook
    s = connect()
    # send get to root, get login link
    s, login = initial_get(s)
    # send get to login link
    s, login_recv, cookie, csrfmiddlewaretoken = login_get(s, login)
    s, msg_back = send_creds(s, login, cookie, csrfmiddlewaretoken)
    print(msg_back)

    #print("logged in", msg_back.head)
    #print("loggined in", msg_back)





if __name__ == "__main__":
    crawl()


