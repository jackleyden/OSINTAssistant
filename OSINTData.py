import json
import requests
import threading
import time

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
    
    def mispFullSearch(self, value):
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
            if value in x: print(value+" detected in: "+i)
                
        # https://www.dan.me.uk/torlist/
        AllFeeds = ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "https://check.torproject.org/torbulkexitlist",
                "https://cybercrime-tracker.net/all.php",
                "https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt",
                "https://home.nuug.no/~peter/pop3gropers.txt",
                "https://openphish.com/feed.txt",
                "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
                "https://cinsscore.com/list/ci-badguys.txt",
                "https://lists.blocklist.de/lists/all.txt",
                "https://dataplane.org/vncrfb.txt",
                "https://dataplane.org/sshpwauth.txt",
                "https://dataplane.org/sipregistration.txt",
                "https://dataplane.org/sipquery.txt",
                "https://dataplane.org/sipinvitation.txt",
                "http://vxvault.net/URL_List.php",
                "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                "https://cybercrime-tracker.net/ccamlist.php",
                "https://cybercrime-tracker.net/ccamgate.php",
                "https://blocklist.greensnow.co/greensnow.txt",
                "https://mirai.security.gives/data/ip_list.txt",
                "https://malsilo.gitlab.io/feeds/dumps/url_list.txt",
                "https://malsilo.gitlab.io/feeds/dumps/ip_list.txt",
                "https://malsilo.gitlab.io/feeds/dumps/domain_list.txt",
                "https://malshare.com/daily/malshare.current.all.txt"]
        j=-1
        for i in AllFeeds:
            j+=1
            proc=threading.Thread(target=OSINTData.loopfeeds, args=(self, i, value))
            proc.start()
            if (j%4 == 0):
                time.sleep(4)
             #proc.terminate()
        time.sleep(2)
        print("Scan Complete:")
        
    def loopfeeds(self, i, value):
        state=""
        x=requests.get(i, headers=self.headers).text
        if value in x: print("ALERT: " + i)

        
if __name__ == "__main__":
    category=input("Category: ")
    value=input("Value: ")
    investigation = OSINTData()
    investigation.talosintelligence(value)
    investigation.greynoise(value)
    #investigation.haveibeenpwned(value)
    #investigation.misp_ipsum(value)
    investigation.mispFullSearch(value)
