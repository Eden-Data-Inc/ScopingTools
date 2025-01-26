# PentestTools

Automate everything you can with our PentestTools automation framework. It's easy to copy a module sample and create your own modules.

run "python PentestTools.py -h" for help
run "python PentestTools.py" for a list of modules

Add your own modules in [PentestTools/modules](https://github.com/integsec/PentestTools/tree/main/PentestTools/modules)

In that folder, you will also find the following files:
- sample_module.py: a simple example module, suitable to be copied when starting a new module
- TLSv1_Test.py: Tests for TLSv1 support
- TLSv11_Test.py: Tests for TLSv1.1 support
- ServerBanner_Test: Test for Server headers in HTTP Response

To implement a module, you only need 2 functions
- parse_args: to parse command line arguments
- run: to run your check and create test results

Test Results should be put in a TestResult object. This object contains four properties:
- target: what target are we checking
- check: what check are we doing
- status: what is the status (vulnerable, not vulnerable, check failure)
- details: any additional details that might be useful in the output

![image](PT.PNG)

Running all modules with various output formats against www.edendata.com:

```$ **python .\PentestTools.py all -t www.edendata.com**
Running example module against target: www.edendata.com
Target: www.edendata.com, Check: Server Banner, Status: not vulnerable, Details: {'Server': 'Not found'}
Target: www.edendata.com, Check: TLSv1.1 in Use, Status: not vulnerable, Details: {'protocol': 'TLSv1.1', 'error': '[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)'}
Target: www.edendata.com, Check: TLSv1 in Use, Status: not vulnerable, Details: {'protocol': 'TLSv1', 'error': '[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)'}

$ **python .\PentestTools.py --output=csv all -t www.edendata.com**
Running example module against target: www.edendata.com
www.edendata.com,Server Banner,not vulnerable,{"Server": "Not found"}
www.edendata.com,TLSv1.1 in Use,not vulnerable,{"protocol": "TLSv1.1", "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"}
www.edendata.com,TLSv1 in Use,not vulnerable,{"protocol": "TLSv1", "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"}

$ **python .\PentestTools.py --output=xml all -t www.edendata.com**
Running example module against target: www.edendata.com
<result><target>www.edendata.com</target><check>Server Banner</check><status>not vulnerable</status><details><Server>Not found</key></details></result>
<result><target>www.edendata.com</target><check>TLSv1.1 in Use</check><status>not vulnerable</status><details><protocol>TLSv1.1</key><error>[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)</key></details></result>
<result><target>www.edendata.com</target><check>TLSv1 in Use</check><status>not vulnerable</status><details><protocol>TLSv1</key><error>[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)</key></details></result>

$ **python .\PentestTools.py --output=json all -t www.edendata.com**
Running example module against target: www.edendata.com
[
  {
    "target": "www.edendata.com",
    "status": "not vulnerable",
    "check": "Server Banner",
    "details": {
      "Server": "Not found"
    }
  }
]
[
  {
    "target": "www.edendata.com",
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
    "target": "www.edendata.com",
    "status": "not vulnerable",
    "check": "TLSv1 in Use",
    "details": {
      "protocol": "TLSv1",
      "error": "[SSL: NO_CIPHERS_AVAILABLE] no ciphers available (_ssl.c:1006)"
    }
  }
]```