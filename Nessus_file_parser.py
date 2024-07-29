import os
import xml.etree.ElementTree as ET
from collections import defaultdict

def parse_nessus_file(file_path):
    vulnerabilities = []


    ## SCARS ON THE BACK ARE SWORDSMEN SHAME 

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for report_host in root.findall(".//ReportHost"):
            host_ip = report_host.get("name")

            for item in report_host.findall(".//ReportItem"):
                risk_factor_element = item.find(".//risk_factor")
                if risk_factor_element is not None:
                    risk_factor = risk_factor_element.text.strip()
                else:
                    risk_factor = "N/A"

                vulnerability_name = item.get("pluginName")

                # Collect CVE IDs
                cve_elements = item.findall(".//cve")
                cve_ids = [cve.text.strip() for cve in cve_elements] if cve_elements else []

                # Collect CWE IDs
                cwe_elements = item.findall(".//cwe")
                cwe_ids = [cwe.text.strip() for cwe in cwe_elements] if cwe_elements else []

                # Combine CVE and CWE IDs
                combined_ids = cve_ids + cwe_ids if cve_ids or cwe_ids else ["N/A"]

                solution = item.find(".//solution").text.strip() if item.find(".//solution") is not None else "N/A"
                reference = item.find(".//see_also").text.strip() if item.find(".//see_also") is not None else "N/A"
                description = item.find(".//description").text.strip() if item.find(".//description") is not None else "N/A"
                port = item.get('port', '0')

                ip_port = host_ip if port == '0' else f"{host_ip} (Port No.: {port})"

                # Adjust the severity for specific vulnerabilities
                if vulnerability_name == "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)":
                    risk_factor = "Low"
                elif vulnerability_name == "SSL Version 2 and 3 Protocol Detection":
                    risk_factor = "High"

                if risk_factor in ["Critical", "High", "Medium", "Low"]:
                    vulnerabilities.append({
                        "IP(Port)": ip_port,
                        "Vulnerability Name": vulnerability_name,
                        "CVE/CWE IDs": ', '.join(combined_ids),
                        "Severity": risk_factor,
                        "Recommendation": solution,
                        "Reference": reference,
                        "Description": description
                    })

    except Exception as e:
        print("Error parsing Nessus file:", e)

    # Sort the vulnerabilities by severity: Critical, High, Medium, Low
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["Severity"], 5))

    # Merge vulnerabilities based on vulnerability name
    merged_vulnerabilities = merge_vulnerabilities(vulnerabilities)

    return merged_vulnerabilities

def merge_vulnerabilities(vulnerabilities):
    merged_vulnerabilities = defaultdict(lambda: {
        "IPs": set(),
        "Vulnerability Names": set(),
        "CVE/CWE IDs": set(),
        "Severity": None,
        "Recommendation": None,
        "Reference": None,
        "Description": None
    })

    for vuln in vulnerabilities:
        vulnerability_name = vuln["Vulnerability Name"]
        
        # Check if the vulnerability name already exists in merged_vulnerabilities
        if vulnerability_name in merged_vulnerabilities:
            # Merge IP addresses, CVE/CWE IDs, and update other fields
            merged_vulnerabilities[vulnerability_name]["IPs"].add(vuln["IP(Port)"])
            merged_vulnerabilities[vulnerability_name]["CVE/CWE IDs"].update(vuln["CVE/CWE IDs"].split(', '))
            merged_vulnerabilities[vulnerability_name]["Severity"] = vuln["Severity"]
            if merged_vulnerabilities[vulnerability_name]["Recommendation"] is None:
                merged_vulnerabilities[vulnerability_name]["Recommendation"] = vuln["Recommendation"]
            if merged_vulnerabilities[vulnerability_name]["Reference"] is None:
                merged_vulnerabilities[vulnerability_name]["Reference"] = vuln["Reference"]
            if merged_vulnerabilities[vulnerability_name]["Description"] is None:
                merged_vulnerabilities[vulnerability_name]["Description"] = vuln["Description"]
        else:
            # If the vulnerability name is not in merged_vulnerabilities, add new entry
            merged_vulnerabilities[vulnerability_name]["IPs"].add(vuln["IP(Port)"])
            merged_vulnerabilities[vulnerability_name]["Vulnerability Names"].add(vulnerability_name)
            merged_vulnerabilities[vulnerability_name]["CVE/CWE IDs"].update(vuln["CVE/CWE IDs"].split(', '))
            merged_vulnerabilities[vulnerability_name]["Severity"] = vuln["Severity"]
            merged_vulnerabilities[vulnerability_name]["Recommendation"] = vuln["Recommendation"]
            merged_vulnerabilities[vulnerability_name]["Reference"] = vuln["Reference"]
            merged_vulnerabilities[vulnerability_name]["Description"] = vuln["Description"]

    result = []

    for vulnerability_name, merged_data in merged_vulnerabilities.items():
        result.append({
            "IP(Port)": ', '.join(merged_data["IPs"]),
            "Vulnerability Name": vulnerability_name,
            "CVE/CWE IDs": ', '.join(merged_data["CVE/CWE IDs"]) if merged_data["CVE/CWE IDs"] else "N/A",
            "Severity": merged_data["Severity"],
            "Recommendation": merged_data["Recommendation"],
            "Reference": merged_data["Reference"],
            "Description": merged_data["Description"]
        })

    return result

def generate_html_report(vulnerabilities, output_file_path):
    severity_color = {
        "Critical": {"order": 1, "color": "#C00000"},
        "High": {"order": 2, "color": "#FF0000"},
        "Medium": {"order": 3, "color": "#ED7D31"},
        "Low": {"order": 4, "color": "#70AD47"}
    }

    html_content = """
    <html>
    <head>
        <title>Nessus Scan Report</title>
        <style>
            body {
                font-family: Verdana, Geneva, sans-serif;
                font-size: 10pt;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #1F497D;
                color: white;
                text-align: center;  /* Center align table headers */
            }
            .center {
                text-align: center;  /* Center align specific columns */
                vertical-align: middle;
            }
            .severity-critical {
                font-weight: bold;
                color: #C00000;  /* Red color for Critical */
            }
            .severity-high {
                font-weight: bold;
                color: #FF0000;  /* Red color for High */
            }
            .severity-medium {
                font-weight: bold;
                color: #ED7D31;  /* Orange color for Medium */
            }
            .severity-low {
                font-weight: bold;
                color: #70AD47;  /* Green color for Low */
            }
            .bold {
                font-weight: bold;
                color: black;  /* Black color for vulnerability name */
            }
        </style>
    </head>
    <body>
        <table>
            <tr>
                <th>S.No.</th>
                <th class="center">Affected Asset i.e. IP/URL/Application etc.</th>
                <th>Observation / Vulnerability Title</th>
                <th class="center">CVE-ID / CWE-ID</th>
                <th>Severity</th>
                <th>Recommendation</th>
                <th>Reference</th>
                <th>New or Repeated Observation</th>
            </tr>
    """

    for i, vuln in enumerate(vulnerabilities, start=1):
        # Determine the severity class
        severity_class = f"severity-{vuln['Severity'].lower()}"
        
        # Build HTML row with bold and centered severity and bold vulnerability name
        html_content += f"""
            <tr>
                <td class="center">{i}</td>
                <td class="center">{vuln['IP(Port)']}</td>
                <td><span class="bold">{vuln['Vulnerability Name']}</span></td>
                <td class="center">{vuln['CVE/CWE IDs']}</td>
                <td class="center"><span class="{severity_class}">{vuln['Severity']}</span></td>
                <td>{vuln['Recommendation']}</td>
                <td>{vuln['Reference']}</td>
                <td class="center">New</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """

    with open(output_file_path, 'w') as file:
        file.write(html_content)

def generate_detailed_findings(vulnerabilities, output_file_path):
    html_content = """
    <html>
    <head>
        <title>Detailed Findings</title>
        <style>
            body {
                font-family: Verdana, Geneva, sans-serif;
                font-size: 10pt;
                line-height: 1.5;
            }
            .bold {
                font-weight: bold;
            }
            .separator {
                padding: 10px 0;
            }
        </style>
    </head>
    <body>
    """

    for index, vuln in enumerate(vulnerabilities, start=1):
        html_content += f"""
        <div>
            <p><span class="bold">Observation {index}:</span></p>
            <p><span class="bold">i. Observation / Vulnerability Title:</span> {vuln['Vulnerability Name']}</p>
            <p><span class="bold">ii. Affected Asset i.e. IP/URL/Application etc.:</span> {vuln['IP(Port)']}</p>
            <p><span class="bold">iii. Detailed Observation:</span> {vuln['Description']}</p>
            <p><span class="bold">iv. CVE/CWE ID:</span> {vuln['CVE/CWE IDs']}</p>
            <p><span class="bold">v. Severity:</span> {vuln['Severity']}</p>
            <p><span class="bold">vi. Recommendation:</span> {vuln['Recommendation']}</p>
            <p><span class="bold">vii. Reference:</span> {vuln['Reference']}</p>
        """

        if 'New or Repeat observation' in vuln:
            html_content += f"""
            <p><span class="bold">viii. New or Repeat observation:</span> {vuln['New or Repeat observation']}</p>
            """
        else:
            html_content += f"""
            <p><span class="bold">viii. New or Repeat observation:</span> New</p>
            """

        html_content += f"""
            <p><span class="bold">ix. Proof of Concept:</span> Step I: Go the URL: [Screenshot]</p>
        </div>
        """

        # Add separator between findings
        html_content += """
        <div class="separator">+++++++++++++++++++++++++++++++++++++++++++++++++++++++++</div>
        """

    html_content += """
    </body>
    </html>
    """

    with open(output_file_path, 'w') as file:
        file.write(html_content)

if __name__ == "__main__":
    print("\n********************************************")
    print("*                                          *")
    print("*   --   NESSUS FILE PARSER --             *")
    print("*                                          *")
    print("********************************************\n")

    nessus_file_path = input("Enter the location of the Nessus file: ")

    if nessus_file_path and os.path.exists(nessus_file_path):
        parsed_vulnerabilities = parse_nessus_file(nessus_file_path)
        nessus_file_name = os.path.basename(nessus_file_path)
        nessus_file_name_without_extension = os.path.splitext(nessus_file_name)[0]

        # Generate HTML report
        output_html_file_path = os.path.join(os.path.dirname(nessus_file_path), f"va_table_{nessus_file_name_without_extension}.html")
        generate_html_report(parsed_vulnerabilities, output_html_file_path)
        print(f"HTML report generated: {output_html_file_path}")

        # Generate detailed findings report as HTML
        output_detailed_file_path = os.path.join(os.path.dirname(nessus_file_path), f"detail_finding_{nessus_file_name_without_extension}.html")
        generate_detailed_findings(parsed_vulnerabilities, output_detailed_file_path)
        print(f"Detailed findings generated: {output_detailed_file_path}")

    else:
        print("\nA R A - A R A\nCheck the Nessus file path and try again.\n")



#-----------------------------------------------------------------------------------------------------------------------------------------

## POWER ISN'T DETERMINED BY YOUR SIZE

        ##BUT BY THE SIZE OF YOUR HEART & DREAMS

                        # FUTURE PIRATE KING " MONKEY D. LUFFY " 

 #-----------------------------------

# CREATED BY :: PUSHKAR SINGH
