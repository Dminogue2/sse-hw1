import json
import xml.etree.ElementTree as xml
import requests
import sqlite3
import re

# apiKey = "dddd98eb-9466-4bff-bde5-8b9e24db55ef"
apiKey = "2cf9f1fc-61d5-4ac9-91eb-c3e5933c97b3"

CREATEREC = 'CREATE TABLE "RECORD" ("id"	TEXT, "vendor"	TEXT NOT NULL, "product"	TEXT NOT NULL, "version"	TEXT, "versionStart"	TEXT, "versionEnd"	TEXT, "parent"	TEXT);'
CREATECVE = 'CREATE TABLE "CVE" ("id"	TEXT UNIQUE, "desc"	TEXT, "sev"	TEXT, "recs"	TEXT NOT NULL, PRIMARY KEY("id"));'
COMPRESS1 = 'CREATE TABLE "TEMP" ("id"	TEXT, "vendor"	TEXT NOT NULL, "product"	TEXT NOT NULL, "version"	TEXT, "versionStart"	TEXT, "versionEnd"	TEXT, "parent"	TEXT, PRIMARY KEY("id"));'
COMPRESS2 = 'INSERT INTO "TEMP" SELECT id, vendor, product, version, versionStart, versionEnd, ("[" || group_concat(parent, ", ") || "]") FROM RECORD GROUP BY id;'
COMPRESS3 = 'DROP TABLE RECORD;'
COMPRESS4 = 'ALTER TABLE "TEMP" RENAME TO RECORD;'

def populate():
    # Obtain the JSON data
    baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cont = True
    toSend = {'startIndex': 0, 'noRejected': ''}

    db = sqlite3.connect('NVD-SQL.sqlite')
    '''
    2 Related Tables:
     MATCH: Carry the searchable nodes
      ID: Match ID (PK)
      vendor
      product
      version: Null only when versionStart/End populated
      operation: copied from the cve, only require backwards search if and (0 for or or other, 1 for and)
      versionStart
      versionEnd
      parent: CVE-ID it is linked to
     CVE: Carry exploit IDs
      ID
      desc
      severity
      nodeList: list of match IDs in a list such as [{node}, ...] where node=['0/1', 'mId', ...]. Only used when looking for AND dependencies
    '''
    try:
        db.execute('DROP TABLE RECORD') # Starting from scratch, if no file then these will throw error that can be ignored
        db.execute('DROP TABLE CVE')
    except sqlite3.OperationalError:
        pass
    db.execute(CREATEREC)
    db.execute(CREATECVE)
    db.commit()
    while cont:
        response = requests.get(baseUrl, params=toSend, headers={'apiKey': apiKey}) # API Only allows 2000 cve's to be requested at once
        if 200 <= response.status_code < 300:  # Successful operation
            data = response.json()
            print(f"Parsing data: {data['startIndex']} - {data['startIndex'] + data['resultsPerPage']} out of {data['totalResults']}")
            toSend['startIndex'] = data['startIndex'] + data['resultsPerPage']
            if toSend['startIndex'] >= data['totalResults']:  # Have read entire database, stop after this operation
                cont = False
            for cve in data['vulnerabilities']:
                if 'configurations' not in cve['cve']:  # Skip all reports in "Awaiting Analysis, Undergoing Analysis, or Rejected" state
                    continue
                ID = cve['cve']['id']
                desc = next((d['value'] for d in cve['cve']['descriptions'] if d['lang'] == 'en'), '')
                #desc = desc.replace('"', '\'')
                # Search both types of metrics available and chose the first one on the list to report. This prioritized v3.1 over v3.0 over v2
                severity = ""
                if 'metrics' in cve['cve']:
                    if 'cvssMetricV2' in cve['cve']['metrics'].keys():
                        severity = cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
                    if 'cvssMetricV30' in cve['cve']['metrics'].keys():
                        severity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    if 'cvssMetricV31' in cve['cve']['metrics'].keys():
                        severity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                cpe = list()
                for entry in cve['cve']['configurations']:
                    for node in entry['nodes']:
                        matches = list()
                        if 'cpeMatch' not in node:
                            continue
                        for match in node['cpeMatch']:
                            if match['vulnerable']:
                                matches.append(
                                    {'id': match['matchCriteriaId'],
                                     'vendor': match['criteria'].split(":")[3],
                                     'product': match['criteria'].split(":")[4],
                                     'version': match['criteria'].split(":")[5],
                                     'versionStart': match['versionStartIncluding'] if 'versionStartIncluding' in match else '',
                                     'versionEnd': match['versionEndExcluding'] if 'versionEndExcluding' in match else ''})
                        cpe.append({'matches': matches, 'op': node['operator']})
                nodeString = list()
                for entry in cpe:
                    toAdd = [1 if entry['op'] == 'AND' else 0]
                    for match in entry['matches']:
                        toAdd.append(match['id'])
                        INSERTREC = f'INSERT INTO RECORD (id, vendor, product, version, versionStart, versionEnd, parent) VALUES (?, ?, ?, ?, ?, ?, ?)'
                        # Add record to match table
                        db.execute(INSERTREC,
                                   [match["id"], match["vendor"], match["product"], match["version"], match["versionStart"], match["versionEnd"], f'"{ID}"'])
                    nodeString.append(toAdd)
                nodeString = json.dumps(nodeString)
                # Do insert operation
                INSERTCVE = f'INSERT INTO CVE (id, desc, sev, recs) VALUES (?, ?, ?, ?)'
                db.execute(INSERTCVE, [ID, desc, severity, nodeString]) # Add cve to cve table
                #db.commit()
        else:  # Unsuccessful Operation, do not retry for now
            print(f"Could not complete response with GET: {json.dumps(toSend)}")
            print(f"\t{response.text}")
            exit(1)
    # Compress like entries in the table and clean up discarded pages
    db.execute(COMPRESS1)
    db.execute(COMPRESS2)
    db.execute(COMPRESS3)
    db.execute(COMPRESS4)
    db.commit()
    db.execute("VACUUM")
    db.commit()
    db.close()
    return


# Parse through pom xml file dependencies
def parse(path: str):
    dependencies = list()
    pom = xml.parse(path)
    for dep in pom.iter('{http://maven.apache.org/POM/4.0.0}dependency'):
        toAdd = {"groupId": dep.find('{http://maven.apache.org/POM/4.0.0}groupId').text, # Assume that the last part of the url is the vendor name
                 "artifactId": dep.find('{http://maven.apache.org/POM/4.0.0}artifactId').text,
                 "version": dep.find('{http://maven.apache.org/POM/4.0.0}version').text,
                 "fullName": dep.find('{http://maven.apache.org/POM/4.0.0}artifactId').text}
        if len(toAdd['groupId'].split('.')) > 1:
            toAdd['groupId'] = ('.' if len(toAdd['groupId'].split('.')[-2]) == 0 else '') + toAdd['groupId'].split('.')[-1]
        if len(toAdd['artifactId'].split('.')) > 1:
            toAdd['artifactId'] = ('.' if len(toAdd['artifactId'].split('.')[-2]) == 0 else '') + toAdd['artifactId'].split('.')[-1]
        dependencies.append(toAdd)
    return dependencies


DEPSELECT = 'SELECT id, version, versionStart, versionEnd, parent, vendor, product FROM RECORD WHERE vendor LIKE ("%" || :ven || "%") AND product LIKE ("%" || :prod || "%")'

# Search database for cpe's related to dependencies. Uses partial string matching in sqlite to determine partial matches
#  This is partially prone to false positives if matching to longer vendor/product names, especially forks (.net and .net_explorer)
def findDep(db: sqlite3.Connection, target: dict):
    recordList = list()
    sel = db.execute(DEPSELECT, {"ven": target['groupId'], "prod": target['artifactId']})
    if sel.arraysize == 0:
        return []
    for entry in sel:
        # Check if version is correct
        if (target['version'] != entry[1] and entry[1] not in ['*', '-', '']) or not versionWithin(
                target['version'].replace('-', '.').split('.')
                , entry[2].replace('-', '.').split('.')
                , entry[3].replace('-', '.').split('.')): # Test if
            continue
        # If so, create record
        recordList.append({"groupId": target['groupId']
                              , "artifactId": target['artifactId']
                              , "version": entry[1]
                              , "startVersion": entry[2]
                              , "endVersion": entry[3]
                              , "cpeid": entry[0]
                              , "cveid": json.loads(entry[4])
                              , "fullName": target['fullName']}
                          )

    return recordList

# Helper function to determine if the version is within a range. Does this by translating it into a number using version2num
def versionWithin(targ: list, low: list, high: list):
    if low == ['']: # If no low list specified, then assume that all versions before high are vulnerable
        low = targ
    if high == ['']: # If no high list specified, then assume that all versions past low are vulnerable
        high = targ
    tn = version2num(targ)
    ln = version2num(low)
    hn = version2num(high)
    return ln <= tn <= hn


VERSIONFRACTION = 10000 # Assume that each version part will not exceed this number

# Helper function to translate a version number into a float by multiplying by decreasing fractions
#  If a version part is greater than 5 digits, then this will not work however this is a rare edge case
#  Additionally detects if the part has non-numeric components and subtracts a small amount to place it in sequence
#   This is done to account for alpha/beta branches which should be placed lower than their numeric counterparts
def version2num(version: list):
    tn = 0
    for i in range(len(version)):
        try:
            tn += float(version[i]) * pow(VERSIONFRACTION, -i)
        except ValueError:
            digits = re.findall(r'\d+', version[i])[0]
            tn += ((float(digits) if len(digits) > 0 else 0) - 0.1) * pow(VERSIONFRACTION, -i)
    return tn


CVESELECT = 'SELECT * FROM CVE WHERE id = :cveid'

# Checks through the cve and cvp lists to find any inconsistencies relating to AND conditionals
def checkCve(db: sqlite3.Connection, cveList: list, cpeList: list):
    toRet = {}
    count = 0
    for cve in cveList:
        sel = db.execute(CVESELECT, {"cveid": cve})
        for entry in sel:
            valid = False
            for cpenode in json.loads(entry[3]):
                if cpenode[0] != 1:
                    for i in range(1, len(cpenode)):
                        if cpenode[i] in cpeList:
                            valid = True
                            break
                else:
                    valid = True
                    for i in range(1, len(cpenode)):
                        if cpenode[i] not in cpeList:
                            valid = False
                            break
                if valid:
                    break
            if valid:
                toRet[entry[0]] = {"desc": entry[1], "sev": entry[2]}
                count += 1
    return count, toRet

# Outputs the results of the program to a file dependent on the path provided
def printVulnerabilities(path: str, report: dict, cve: dict):
    if path.find('.') != -1:
        path = path[0:path.find('.')]
    out = open(f"report-{path}.txt", 'w+')
    if len(report) == 0:
        out.write("No Security Vulnerabilities Detected")
        out.close()
        return
    out.write("Known Security Vulnerabilities Detected:\n")
    for product in report.keys():
        outstr = f"\nDependency: {product}\n"
        for vuln in report[product]:
            outstr += " Version"
            if vuln['startVersion'] == vuln['endVersion']:
                outstr += f": {vuln['version']}"
            else:
                outstr += f"s: " + (f">= {vuln['startVersion']} " if vuln['startVersion'] != '' else '') + (f"<= {vuln['endVersion']}" if vuln['endVersion'] != '' else '')
            outstr += "\n"
            for linkedcve in vuln['cveid']:
                desc = cve[linkedcve]['desc'].replace('\n', '')
                outstr += f" *{linkedcve}" + (f": Severity - {cve[linkedcve]['sev']}" if cve[linkedcve]['sev'] != '' else '') + f"\n  {desc}\n"
        out.write(outstr)
    out.close()
    return
