from shodan import Shodan
from shodan.cli.helpers import get_api_key
import csv
data = ["IP", "CVE", "CVSS"]
api = Shodan(get_api_key())
with open('Shodan.csv', 'w') as file:
    writer = csv.writer(file)
    writer.writerow(data)
limits = 5
i = 0
results = api.search('org:tdc has_vuln:true', limit=limits)
print('Results found: {}'.format(results['total']))
for result in results['matches']:
    
    i = i+1
    print(result['vulns'])
    print('her begynder det andet')
    print('IP: {}'.format(result['ip_str']))
    for item in result['vulns']:
        CVE = item.replace('!','')
        print('Vulns: %s' % item)
        print('CVSS: {}'.format(result['vulns'][item]['cvss']))
        data = [result['ip_str'], item, result['vulns'][item]['cvss']]
        with open('Shodan.csv', 'a') as file:
            writer = csv.writer(file)
            writer.writerow(data)
