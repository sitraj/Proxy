import re
from bs4 import BeautifulSoup, SoupStrainer
Payloads = {'target_host.*': 'target_host=google.com&dns-lookup-php-submit-button=Lookup+DNS'}

def RequestHandler(req,req_body,thread):
    if req_body is not None:
        for key, value in Payloads.iteritems():
            if re.search(key, req_body):
                ModifiedReqBody = re.sub(key, value, req_body)
                return ModifiedReqBody, thread
            else:
                return None, None
    else:
        return None, None
            
def ResponseHandler(req, req_body, res, res_body_plain, Thread, ThreadID):
    #print Thread
    #print ThreadID
    if res_body_plain == '':
        pass
    elif Thread == ThreadID:
        for key,value in Payloads.iteritems():
            pass
            #print key
            #print value
        if re.search("<script>alert\(1\)</script>", res_body_plain):
            print "XSS found"
        else:
            print "No xss present"
    
                       
        