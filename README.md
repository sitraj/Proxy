# Proxy

sslproxy.py - Web Application Proxy and XSS Scanner

A tool by Shounak Itraj

How to Use:

1) Add ca.crt in your browser's Trusted certificate store.
2) Enable Proxy in browser with IP 127.0.0.1 and port 8081
	a. If you are using Mozilla Firefox then go to, Settings -> Advabced -> Network -> Settings -> 'Manual Proxy Configuration'
	b. If you are using Google Chrome then go to, Settings -> 'Change Proxy Setting' -> Connections -> 'Lan Settings' -> Select 'Use Proxy Server for your LAN' -> Enter IP 127.0.0.1 and port 8081

Installation:

Type the following in the terminal.

git clone https://github.com/shounakitraj/Proxy.git /opt/Proxy

The tool works on Python 2.7 and you should have mechanize installed. It requires following libraries to be installed,

|Library|Ubuntu|Windows|
|----------|:-------------:|------:|
|BeautifulSoup|pip install BeautifulSoup|C:\Python27\Scripts\easy_install.exe BeautifulSoup|
|mechanize|pip install mechanize|C:\Python27\Scripts\easy_install.exe mechanize|


Usage:

1) Run sslproxy.py, this will run on 127.0.0.1:8081.
2) Enter URL/Domain in browser where you have set the proxy.

Payloads

If you have found a XSS vulnerability, you can try the following payloads. http://pastebin.com/J1hCfL9J

Description:

1) The response and request headers will be stored in headers.txt in directory where your sslproxy.py file exists
2) The response receieved from server will be stored in directory named with the Domain you are visiting. E.g. if you are visiting www.imdb.com, the toll will create directory named 'www.imdb.com' and response will be store in this directory.
3) It also checks if there are any fields which have 'input' type as 'Text' in HTML page, if it finds any the HTML INPUT tag is stored in file with <domainname>.txt
4) It also checks if the site is vulnerable to Reflected XSS by sending few XSS Payloads and checks if those are exactly present in response.

NOTE:

Mail me if you encounter any errors (shounakitraj@gmail.com). You can also post your problems on the website. I'll try my best to respond as soon as possible.
