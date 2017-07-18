# HTTP and HTTPS Proxy

sslproxy.py - Web Application Proxy

A tool by Shounak Itraj

### How to Use:

1) Add ca.crt in your browser's Trusted certificate store.
2) Enable Proxy in browser with IP 127.0.0.1 and port 8081
	a. If you are using Mozilla Firefox then go to, Settings -> Advabced -> Network -> Settings -> 'Manual Proxy Configuration'
	b. If you are using Google Chrome then go to, Settings -> 'Change Proxy Setting' -> Connections -> 'Lan Settings' -> Select 'Use Proxy Server for your LAN' -> Enter IP 127.0.0.1 and port 8081

### Installation:

Type the following in the terminal.

git clone https://github.com/shounakitraj/Proxy.git /opt/Proxy

The tool works on Python 2.7 and you should have mechanize installed. It requires following libraries to be installed,

|Library|Ubuntu|Windows|
|:----------:|:-------------:|:------:|
|BeautifulSoup|pip install BeautifulSoup|C:\Python27\Scripts\easy_install.exe BeautifulSoup|
|mechanize|pip install mechanize|C:\Python27\Scripts\easy_install.exe mechanize|


### Usage:

1) Run sslproxy.py, this will run on 127.0.0.1:8081.
2) Enter URL/Domain in browser where you have set the proxy.

### Description:

#### Tool:
This tool works as proxy server between web application and client. When Client tries to connect to server and when traffic comes to the tool. This tool stores request headers and send the traffic to server. When it gets response from server, the response is stored in directory format, where the directory name is the same name as Domain you are visiting. e.g. if you are visiting www.imdb.com, the toll will create directory named 'www.imdb.com' and response will be store in this directory.

The request and response headers are stored in headers.txt file in the current directory.

#### Plugins:
You can also load plugins in this proxy, the only thing you need to do is, create some directory with your plugin name in 'plugins' directory. Then create file named '__init__.py'. Thus tool will automatically load your plugin and will show message on console like, 'Loading plugin xssfind'

I have created few sample plugins as follows,
* xssfind - This plugin has two functions
	* FindText(htmldata, Filename) - The htmldata contains the response from server while 'Filename' is the domainname, which is required to create the file to store output of function in <Filename>.txt. This function will accept htmldata and render through data and check if there are any HTML INPUT tags which have 'Type=text" in it. If it finds any the output is stored in previously mentioned txt file.
	* FindXSS(link) - This functions accepts one parameter which is URL. This function will get the URL and check if it has any XSS vulnerable 'TextControl' present. In short it is extended version of FindText function where it also checks if INPUT tag of HTML haveing 'Tyep=text' is vulnerable to XSS vulnerability using few sample XSS Paylods. You can add your payloads and check.

* ReqHandle - This plugin is written to search and replace strings from Request headers or Req body. It contains two functions
	* RequestHandler(req,req_body,thread) - This function accepts 3 parameters as, request header, request body and curent thread. Created dictionary which contains list of strings and their respective replacbale value in key,value pair. This function returns Modified Request body and thread. This thread ID is used by ResponseHandler function to check the response from customer for same thread.
 
### NOTE:

Mail me if you encounter any errors (shounakitraj@gmail.com). I'll try my best to respond as soon as possible.




