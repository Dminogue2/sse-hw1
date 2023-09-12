import sys
import sqlite3
from requestParser import populate, parse, findDep, checkCve, printVulnerabilities

sys.argv = ['', 'doAll', 'pom/pom-1.xml']

if len(sys.argv) != 3:
    print("Incorrect Command Line Usage: main.py [mode] [path]")
    exit(1)

if sys.argv[1] == "doAll":
    populate()
elif sys.argv[1] != "detectOnly":
    print("Incorrect Mode. Possible Modes are [doAll, detectOnly]")
    exit(1)

# Parse the pom file to find all dependencies
dependencies = parse(sys.argv[2])

# Find a list of record id's associated with these dependencies
db = sqlite3.connect('NVD-SQL.sqlite')
report = {}
for dep in dependencies:
    for record in findDep(db, dep):
        try:
            report[record['fullName']].append(record)
        except KeyError:
            report[record['fullName']] = [record]

cveList = list() # These lists are used to verify that vulnerabilities are correct, otherwise AND relations may cause false positives
cpeList = list()
for product in report.values():
    for record in product:
        cpeList.append(record['cpeid'])
        for cveid in record['cveid']:
            cveList.append(cveid)

vulnCount, cveVulnerabilities = checkCve(db, cveList, cpeList)
db.close()
printVulnerabilities(sys.argv[2].split('/')[-1], report, cveVulnerabilities)
print(f"Success! {sys.argv[2]} had {vulnCount} vulnerabilities over {len(report.keys())} dependencies")
