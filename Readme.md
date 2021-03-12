# Vulnerability Assessment and Indicator of Compromise (IoC) Scanner

This repository contains a tool to perform the following tasks:

1) Perform a best-effort, black-box scan of your SAP application(s) to quickly assess if they may be vulnerable to:
    - CVE-2020-6287 (RECON)
    - CVE-2020-6207 (EEM Authentication bypass)

2) Perform a basic analysis for Indicators of Compromise (IoCs) leveraging the RECON vulnerability and the EEM Authentication bypass by analyzing SAP application logs.

This tool cannot:

- Guarantee with 100% accuracy whether your SAP applications are vulnerable or not.

- Find all evidence of compromise of an SAP application, all IoCs related to the aforementioned vulnerabilities or post-exploitation activities.

There are, however, several known limitations of this tool and its usage should not be considered a guarantee that SAP applications are either not exposed to CVE-2020-6287 or CVE-2020-6207 (and other vulnerabilities) or that the applications have not been compromised. Several conditions can affect the state of the assessed applications and/or log files, resulting in false positives and/or false negatives.

## Features

This set of tools can help you for the following tasks:

- Detect SAP systems vulnerable to CVE-2020-6287 (RECON)
- Detect SAP systems vulnerable to CVE-2020-6207 (EEM Authentication bypass)
- Detect IoCs in SAP systems logs for both CVEs

If IoCs are identified, it is strongly recommended that you perform an in-depth forensic examination of the evaluated systems (and inter-connected ones), to determine the scope and extent of a potential compromise.

This tool is offered “as is” and without warranty.

## Details

Based on the evidence provided in the Onapsis threat report and the attacks seen on the wild targeting SAP systems, Onapsis decided to release this Open Source tool to help companies that could be exposed to analyze their systems and detect potential compromises.

This tool incudes a previously released check for CVE-2020-6287 (RECON) and a new check for CVE-2020-6207 (EEM Authentication bypass). It allows you either to check if your SAP systems are affected by these issues or scan logs for potential exploitation attempts.

This tool extends our previous script [CVE-2020-6287_RECON-scanner](https://github.com/Onapsis/CVE-2020-6287_RECON-scanner). Thanks to all the people involved in its development.

### CVE-2020-6207 (EEM Authentication bypass)

End User Experience Monitoring (formerly EEM, now UxMon) application is affected by an authentication bypass vulnerability allowing any remote attacker with access to the Solution Manager web interface to abuse its functionality. SAP has released SAP security note #2890213 fixing this issue.

To check if your SAP system is affected by this vulnerability, this tool will issue an `HTTP POST` requests to the affected endpoint, namely, `/EemAdminService/EemAdmin` without using any username or password and checking if the HTTP Response code is `200`.

To detect potential exploitation of this issue this tool will scan Application's log file called `responses.xx.x.trc` where `x` is replace by numbers, looking for entries containing the aforementioned endpoint and its status code.

These files can be found in the following directory:

- Linux: /usr/sap/<SID>/<INSTANCE>/j2ee/cluster/server<N>/log/system/httpaccess/
- Windows: \usr\sap\<SID>\<INSTANCE>\j2ee\cluster\server<N>\log\system\httpaccess\

### CVE-2020-6287 (RECON)

RECON (Remotely Exploitable Code On NetWeaver) is a critical (CVSSv3 10)vulnerability affecting a number of SAP business and technical applications running on top of the SAP NetWeaver Java stack. This vulnerability was discovered by the Onapsis Research Labs, which collaborated closely with SAP to develop and release a patch on July 14, 2020. Given the criticality of this issue, the U.S. DHS CISA, BSI CERT-Bund and several other government agencies released alerts urging SAP customers to protect vulnerable applications, prioritizing internet-facing ones.

To check if your SAP system is affected by RECON this tool will issue an `HTTP GET` requests to the application's end point `/CTCWebService/CTCWebServiceBean` and check the response code.

To scan for indicators of compromise, the script can analyze two different files:

    - applications_xx.y.log
    - responses_xx.y.trc

`applications_xx.y.log` files can be found in:

- Linux: /usr/sap/<SID>/<INSTANCE>/j2ee/cluster/server<X>/log/
- Windows: \usr\sap\<SID>\<INSTANCE>\j2ee\cluster\server<X>\log\

`responses_xx.y.trc` files can be found in:

- Linux: /usr/sap/<SID>/<INSTANCE>/j2ee/cluster/server<X>/log/system/httpaccess/
- Windows: \usr\sap\<SID>\<INSTANCE>\j2ee\cluster\server<X>\log\system\httpaccess\

_Note: Bear in mind that if changes were made to the standard log format configuration, the parsing could fail. In that case, the internal regex should be manually adjusted to reflect the new format._

## Output

- For vulnerability scanning, the tool returns whether CVE-2020-6207 or CVE-2020-6287  was detected on the scanned URLs.
- For IoC scanning, the tool returns all the events that were identified in the logs that could indicate misuse of LM CTC Configuration Management or the EEM Application and which could require additional forensic investigation.

## Installation and prerequisites

The scripts are developed in Python 3 and require you to install the following dependencies:

Python Requests. https://requests.readthedocs.io/en/master/

To use this tool you can set up your environment executing the following commands:

1) python3 -m venv .venv
2) . .venv/bin/activate
3) pip install -r requirements.txt

## Usage

### Vulnerability scanning

To check if your SAP System is vulnerable, execute the following command:

```
python3 ona_defend_vuln.py -u http://sapsystem.company.com:50000/
```

You must execute the script on a system that has a network connection with the target SAP Application being analyzed. The HTTP(s) port of the SAP NetWeaver JAVA Application server should be reachable (that is, for an instance 00, it will be 50000 for HTTP, but it could be exposed through a proxy/load balancer and/or be accessible through other TCP ports such as 80 or 443).

You can also use the -f parameter to assess multiple URLs by providing a file containing all the URLs to be analyzed:

```
python3 ona_defend_vuln.py -f file_with_urls
```

The output of the assessment is sent to stdout. It is possible to dump it into a file in the following way:

```
python3 ona_defend_vuln.py -f file_with_urls >> results
```

### Indicators of Compromise Scanning

For detecting indicators of compromise, execute the following script:

```
python3 ona_defend_ioc.py -f <file_path> -o {csv, json}
```

The script receives a filename and parses the filename to look for IoCs based on usage of the vulnerable applications, EEM or LM CTC application. The following types of files are accepted:

- applications_xx.y.log
- responses_xx.y.trc

Please bear in mind that IoCs for CVE-2020-6207 (EEM Authentication bypass) can be only found in `responses_xx.y.trc` while IoCs for CVE-2020-6287 (RECON) can be found in both logs.

## Additional Resources

For additional information about the RECON vulnerability, the potential business impact, the affected versions and other data points, please review the RECON Threat Report and information available here: [Onapsis / SAP RECON Cybersecurity Vulnerability](https://www.onapsis.com/recon-sap-cyber-security-vulnerability).

The US-CERT in coordination with other international CERTs, released an alert (AA20-195A) to warn organizations about the criticality of this vulnerability. You can read the full alert here: [Critical Vulnerability in SAP NetWeaver AS Java | CISA](https://us-cert.cisa.gov/ncas/alerts/aa20-195a).

The following SAP Notes provide additional information around patch and mitigations to the RECON vulnerability:

- [2948106 FAQ - for SAP Note 2934135](https://launchpad.support.sap.com/#/notes/2948106)
- [2947895 - RECON - SAP Vulnerability](https://launchpad.support.sap.com/#/notes/2947895)
- [2934135 - [CVE-2020-6287] Multiple Vulnerabilities in SAP NetWeaver AS JAVA (LM Configuration Wizard)](https://launchpad.support.sap.com/#/notes/2947895)
- [2939665 - Disable/Enable LM Configuration Wizard | Critical API's in LM Configuration Wizard](https://launchpad.support.sap.com/#/notes/2939665)

For additional information about the EEM Authentication bypass vulnerability (CVE2020-6207) you can check the following resources:

- [2890213 - [CVE-2020-6207] Missing Authentication Check in SAP Solution Manager](https://launchpad.support.sap.com/#/notes/2890213)
- [An Unauthenticated Journey to Root: Pwning Your Company's Enterprise Software Servers](http://i.blackhat.com/USA-20/Wednesday/us-20-Artuso-An-Unauthenticated-Journey-To-Root-Pwning-Your-Companys-Enterprise-Software-Servers-wp.pdf)