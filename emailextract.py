# Extraction of the Global Address List (GAL) on Exchange >=2013 servers via Outlook Web Access (OWA) 
# By Pigeonburger, June 2021 | Modified for Burp proxy support

import requests, json, argparse
import urllib3

# Suppress SSL warnings when using Burp's self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Extract the GAL on Exchange 2013+ via OWA")
parser.add_argument("-i", "--host", dest="hostname", help="Hostname for the Exchange Server", metavar="HOSTNAME", type=str, required=True)
parser.add_argument("-u", "--username", dest="username", help="A username to log in", metavar="USERNAME", type=str, required=True)
parser.add_argument("-p", "--password", dest="password", help="A password to log in", metavar="PASSWORD", type=str, required=True)
parser.add_argument("-o", "--output-file", dest="output", help="Output file (default: global_address_list.txt)", metavar="OUTPUT FILE", type=str, default="global_address_list.txt")
parser.add_argument("--proxy", dest="proxy", help="Proxy URL for interception (e.g. http://127.0.0.1:8080)", metavar="PROXY", type=str, default=None)

args = parser.parse_args()

url = args.hostname
USERNAME = args.username
PASSWORD = args.password
OUTPUT = args.output
PROXY = args.proxy

# Build proxy dict for requests
proxies = {"http": PROXY, "https": PROXY} if PROXY else {}

# Start the session
s = requests.Session()
s.proxies.update(proxies)
s.verify = False  # Disable SSL verification for Burp's self-signed cert

print("Connecting to %s/owa" % url)
if PROXY:
    print("Routing traffic through proxy: %s" % PROXY)

try:
    s.get(url+"/owa")
    URL = url
except requests.exceptions.MissingSchema:
    s.get("https://"+url+"/owa")
    URL = "https://"+url

AUTH_URL = URL+"/owa/auth.owa"
PEOPLE_FILTERS_URL = URL + "/owa/service.svc?action=GetPeopleFilters"
FIND_PEOPLE_URL = URL + "/owa/service.svc?action=FindPeople"

login_data={"username":USERNAME, "password":PASSWORD, 'destination': URL, 'flags': '4', 'forcedownlevel': '0'}
r = s.post(AUTH_URL, data=login_data, headers={'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"})

try:
    session_canary = s.cookies['X-OWA-CANARY']
except:
    exit("\nInvalid Login Details. Login Failed.")
print("\nLogin Successful!\nCanary key:", session_canary)

r = s.post(PEOPLE_FILTERS_URL, headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'GetPeopleFilters'}, data={}).json()

for i in r:
    if i['DisplayName'] == "Default Global Address List":
        AddressListId = i['FolderId']['Id']
        print("Global List Address ID:", AddressListId)
        break

query = None
max_results = 99999

peopledata = {
    "__type": "FindPeopleJsonRequest:#Exchange",
    "Header": {
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": "Exchange2013",
        "TimeZoneContext": {
            "__type": "TimeZoneContext:#Exchange",
            "TimeZoneDefinition": {
                "__type": "TimeZoneDefinitionType:#Exchange",
                "Id": "AUS Eastern Standard Time"
            }
        }
    },
    "Body": {
        "__type": "FindPeopleRequest:#Exchange",
        "IndexedPageItemView": {
            "__type": "IndexedPageView:#Exchange",
            "BasePoint": "Beginning",
            "Offset": 0,
            "MaxEntriesReturned": max_results
        },
        "QueryString": query,
        "ParentFolderId": {
            "__type": "TargetFolderId:#Exchange",
            "BaseFolderId": {
                "__type": "AddressListId:#Exchange",
                "Id": AddressListId
            }
        },
        "PersonaShape": {
            "__type": "PersonaResponseShape:#Exchange",
            "BaseShape": "Default"
        },
        "ShouldResolveOneOffEmailAddress": False
    }
}

r = s.post(FIND_PEOPLE_URL, headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'FindPeople'}, data=json.dumps(peopledata)).json()

userlist = r['Body']['ResultSet']

with open(OUTPUT, 'a+') as outputfile:
    for user in userlist:
        email = user['EmailAddresses'][0]['EmailAddress']
        outputfile.write(email+"\n")
        print(email)

print("\nFetched %s emails" % str(len(userlist)))
print("Emails written to", OUTPUT)
