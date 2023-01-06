from bs4 import *
import re
import os
import itertools, sys
import json
from pprint import pprint

def bannerArt():

    banner = """\033[34m
    ______               _                                   
    | ___ \             | |                                  
    | |_/ /_ _ _ __ __ _| |_ _ __ ___   ___  _ __   ___ _ __ 
    |  __/ _` | '__/ _` | __| '__/ _ \ / _ \| '_ \ / _ \ '__|
    | | | (_| | | | (_| | |_| | | (_) | (_) | |_) |  __/ |   
    \_|  \__,_|_|  \__,_|\__|_|  \___/ \___/| .__/ \___|_|    v1
                                            | |              
                                            |_|              
                                    
                                       Report Generation Tool
    \033[0m"""

    print(banner)

def main():
    bannerArt()
    global vuln_pattern
    raw_html = _inputHandler()
    vuln_pattern = "box-sizing: border-box; width: 100%; margin: 0 0 10px 0; padding: 5px 10px; background: (#91243E|#DD4B50|#F18C43|#F8C851); font-weight: 700; font-size: 14px; line-height: 20px; color: #fff;"
    rawVulns = raw_html.find_all(name = 'div', style = re.compile(vuln_pattern))

    VulnIP = _getVulnIP(rawVulns)
    VulnDetails = _getVulnDetails(rawVulns)


    print("Output mode:\n1. JSON \n2. Txt \n3. Both")
    choice = input("Enter your Choice: ")
    if choice == "1":
        _generateJson()
        _generateTxt(VulnIP, VulnDetails)
    elif choice == "2":
        _generateTxt(VulnIP, VulnDetails)
    else:
        _generateTxt(VulnIP, VulnDetails)
        _generateJson()


def _generateTxt(VulnIP, VulnDetails):
    border = "\n" + ("=" * 15) + "\n"
    with open("Paratrooper.txt", "w") as outputFile:
        pprint(VulnIP, outputFile, sort_dicts= False)
        pprint(border, outputFile)
        pprint(VulnDetails, outputFile, sort_dicts= False)
        pprint(border,outputFile)

    print("TXT file created in the reports directory.")

def _generateJson():
    print("Feature under development")
    pass

def _getCVE(vuln_references):
        pattern = r"CVE-\d{4}-\d{4,7}"
        CVE_list = re.findall(pattern, vuln_references)
        CVE = ""
        for cve in CVE_list:
            CVE = CVE + ", " + cve
        
        if CVE == "":
            CVE = "N/A"
        else:
            CVE = CVE[2:]

        return CVE

def _getIP(vuln_IP):
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    IPs = re.findall(pattern, vuln_IP)
    IP = ""
    for ip in IPs:
        IP = IP + ", " + ip

    return IP[2:]


def _getVulnIP(raw_html):
    Mapping_list = []
    mapping = {}
    rows = []
    for vuln in raw_html:
        vuln_title = vuln.text.split('-', 1)[1].replace("\n                -\n            \n", "")
        vuln_title = vuln_title[1:]
        try:
            '''
            returns an error when getting the first IP address in the report
            '''
            vuln_IP = vuln.find_next(text="Host Information").parent.find_next('div').find_next('div').text.strip()
            IPs = _getIP(vuln_IP)
            
        except AttributeError:
            '''
            Get the first IP address in the report
            '''
            systems = []
            first_IP = raw_html_global.find(text="Host Information").find_next('tr').find_next('tr').find_next('tr').find_next('td').find_next('td').text.strip()
            print(first_IP)
            # for sib in plugin_output_elem.next_siblings:
            #     if sib.name == 'h2' and "report output too big - ending list here" not in sib.text :
            #         ip, proto = sib.text.split(" ", 1)
            #         proto, port = proto.strip("()").split('/', 1)
            #         systems.append([ip, proto, port])
            #     elif sib.name == 'div' and 'id' in sib.attrs:
            #         # Next vuln
            #         break
            # # Generate rows from the data:
            # for ip, proto, port in systems:
            #     row = {
            #             "Title" : vuln_title,
            #             "IP" : ip,

            #         }
            #     rows.append(row)
            #     return rows

    # print(rows)
       
    #     mapping = {
    #         vuln_title: IPs
    #     }
    #     Mapping_list.append(mapping)

    # Mapping = _removeDuplicates(Mapping_list)

    # # combine output into a single dictionary.
    # print(Mapping)
    # result = {}
    # for item in Mapping:
    #     for key, value in item.items():
    #         if key in result:
    #             if isinstance(result[key], list):
    #                 result[key].append(value)
    #             else:
    #                 result[key] = [result[key], value]
    #         else:
    #             result[key] = value

    # return result

def _getVulnDetails(raw_html):

    details_list = []

    for vuln in raw_html:
        vuln_title = vuln.text.split('-', 1)[1].replace("\n                -\n            \n", "")
        vuln_severity = vuln.find_next(text="Risk Factor").parent.find_next('div').find_next('div').text.strip()
        vuln_description = vuln.find_next(text="Description").parent.find_next('div').find_next('div').text.strip()
        vuln_recommendation = vuln.find_next(text="Solution").parent.find_next('div').find_next('div').text.strip()
        vuln_references = vuln.find_next(text="References").parent.find_next('div').find_next('div').text.strip()
        
        try:
            vuln_references = vuln.find_next(text="References").parent.find_next('div').find_next('div').text.strip()
        except:
            CVE = "N/A"
        else:
            CVE = _getCVE(vuln_references)

        detail = {
            "Title": vuln_title[1:],
            "CVE": CVE,
            "Severity": vuln_severity,
            "Description": vuln_description,
            "Recommendation": vuln_recommendation
        }

        details_list.append(detail)


    details = _removeDuplicates(details_list)
    return details
        
def _removeDuplicates(details_list):
    seen = set()
    details = []
    for detail in details_list:
        detail_tuple = tuple(detail.items()) 
        if detail_tuple not in seen:
            seen.add(detail_tuple)
            details.append(detail)

    return details

def _inputHandler(): 
    html_data = b""
    global raw_html_global
    
   
    while True:
        try:
            path = input("Path to reports folder: ")
            os.chdir(path)
        except FileNotFoundError:
            print("File not found, please try again")
            continue
        else: 
            break

    for file in os.listdir():
        if file.endswith(".html"):
            print(f"found file {file}") 

            with open(file, 'rb') as report:
                html_data = html_data + report.read()
    
    
    raw_html_global = BeautifulSoup(html_data, "html.parser")
    return raw_html_global
            

if __name__ == '__main__':
    main()