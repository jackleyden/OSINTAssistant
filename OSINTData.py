import json
import requests

class OSINTData:
    def __init__(self):
        self.headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
        #'From': '@gmail.com'
    def reader(self, URLs):
        print("----------")
        x=""
        y=""
        for i in URLs:
            try:
                x = requests.get(i, headers=self.headers).json()
            except:
                print(requests.get(i, headers=self.headers).status_code)
                print(requests.get(i, headers=self.headers).text)
                x={"error": i}
                
            y += json.dumps(x, indent=4)
        print(y)

    def talosintelligence(self, ip):
        URLs = ["https://talosintelligence.com/cloud_intel/query_suggestion?query="+ip,
        "https://talosintelligence.com/cloud_intel/ip_reputation?ip="+ip,
        "https://talosintelligence.com/cloud_intel/whois?whois_query="+ip]

        self.reader(URLs)
            
    def greynoise(self, ip):
        URLs = ["https://www.greynoise.io/api/"+ip]
        self.reader(URLs)
        
    def haveibeenpwned(self, email):
        URLs = ["https://haveibeenpwned.com/unifiedsearch/"+email]
        self.reader(URLs)
        
    def misp_ipsum(self, ip): #https://www.misp-project.org/feeds/
        URLs = ["https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt",
                "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt"]
        for i in URLs:
            x=requests.get(i, headers=self.headers).text
            if ip in x: print(ip+" detected in: "+i)


        
if __name__ == "__main__":
    category=input("Category: ")
    value=input("Value: ")
    investigation = OSINTData()
    investigation.talosintelligence(value)
    investigation.greynoise(value)
    #investigation.haveibeenpwned(value)
    investigation.misp_ipsum(value)