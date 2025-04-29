# PentestTools

Automate everything you can with our PentestTools automation framework. It's easy to copy a module sample and create your own modules.

Install dependencies with:\
```pip install -r requirements.txt```

To list down arguments and help:\
```python PentestTools.py -h```

To list down modules:\
```python PentestTools.py```

Add your own modules in [PentestTools/modules](https://github.com/integsec/PentestTools/tree/main/PentestTools/modules)

In that folder, you will also find the following files:
- sample_module.py: a simple example module, suitable to be copied when starting a new module
- TLSv1_Test.py: Tests for TLSv1 support
- TLSv11_Test.py: Tests for TLSv1.1 support
- ServerBanner_Test: Test for Server headers in HTTP Response
- WildcardCert_Test: Test for wildcard certificate presence and usage
- SessionTimeout_Test: Test for proper session timeout implementation
- OwnerInfo_Test: Test for exposed domain ownership data
- CORS_Test: Test for misconfigured Cross-Origin Resource Sharing
- DeprecatedSSL_Test: Test for use of deprecated SSL/TLS versions
- ExposedSitemap_Test: Test for public sitemap.xml exposure
- DNSRecord_Test: Test DNS Security Records (SPF, DKIM, DMARC, CAA)
- SelfSignedSSL_Test: Test for Self-Signed SSL Certificate
- SecurityHeader_Test: Test for Security Headers of a Website
- NonTLS_Test: Test for services accessible over non-TLS HTTP
- VulnCiphers_Test: Test for weak ciphers
- StrictTransport_Test: Test if HSTS is enforced on a website

To implement a module, you only need 2 functions
- parse_args: to parse command line arguments
- run: to run your check and create test results

Test Results should be put in a TestResult object. This object contains four properties:
- target: what target are we checking
- check: what check are we doing
- status: what is the status (vulnerable, not vulnerable, check failure)
- details: any additional details that might be useful in the output

![image](PT.PNG)

Running all modules with various output formats against www.integsec.com:

```
$ python .\PentestTools.py all -t www.integsec.com
Target: www.integsec.com, Check: Server Banner, Status: not vulnerable, Details: {'Server': 'Not found'}
Target: www.integsec.com, Check: TLSv1.1 in Use, Status: not vulnerable, Details: {'protocol': 'TLSv1.1', 'error': '[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)'}
Target: www.integsec.com, Check: TLSv1 in Use, Status: not vulnerable, Details: {'protocol': 'TLSv1', 'error': '[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)'}

$ python .\PentestTools.py --output=csv all -t www.integsec.com
www.integsec.com,Server Banner,not vulnerable,{"Server": "Not found"}
www.integsec.com,TLSv1.1 in Use,not vulnerable,{"protocol": "TLSv1.1", "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"}
www.integsec.com,TLSv1 in Use,not vulnerable,{"protocol": "TLSv1", "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"}

$ python .\PentestTools.py --output=xml all -t www.integsec.com
<result><target>www.integsec.com</target><check>Server Banner</check><status>not vulnerable</status><details><Server>Not found</key></details></result>
<result><target>www.integsec.com</target><check>TLSv1.1 in Use</check><status>not vulnerable</status><details><protocol>TLSv1.1</key><error>[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)</key></details></result>
<result><target>www.integsec.com</target><check>TLSv1 in Use</check><status>not vulnerable</status><details><protocol>TLSv1</key><error>[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)</key></details></result>

$ python .\PentestTools.py --output=json all -t www.integsec.com
[
  {
    "target": "www.integsec.com",
    "status": "not vulnerable",
    "check": "Server Banner",
    "details": {
      "Server": "Not found"
    }
  }
]
[
  {
    "target": "www.integsec.com",
    "status": "not vulnerable",
    "check": "TLSv1.1 in Use",
    "details": {
      "protocol": "TLSv1.1",
      "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"
    }
  }
]
[
  {
    "target": "www.integsec.com",
    "status": "not vulnerable",
    "check": "TLSv1 in Use",
    "details": {
      "protocol": "TLSv1",
      "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"
    }
  }
]```

Future Improvements
- More flexible targetting formats (nmap target specification, host:port so we can test things like TLS issues on multiple ports)
- Output to Plextrac CSV format (https://docs.plextrac.com/plextrac-documentation/product-documentation/reports/findings/csv-findings-templates/using-report-findings-csv-template)
