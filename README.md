# PentestTools

Automate everything you can with our PentestTools automation framework. It's easy to copy a module sample and create your own modules.

run "python PentestTools.py" for help

Add your own modules in [PentestTools/modules](https://github.com/integsec/PentestTools/tree/main/PentestTools/modules)

In that folder, you will also find the following files:
- sample_module.py: a simple example module, suitable to be copied when starting a new module
- TLSv1_Test.py: an example completed module
- TLSv11_Test.py: an example completed module

To implement a module, you only need 2 functions
- parse_args: to parse command line arguments
- run: to run your check and create test results

Test Results should be put in a TestResult object. This object contains four properties:
- target: what target are we checking
- check: what check are we doing
- status: what is the status (vulnerable, not vulnerable, check failure)
- details: any additional details that might be useful in the output

![image](PT.PNG)

Running all modules with json output against www.integsec.com:

```> python .\PentestTools.py --all --output=json all -t www.integsec.com
Pentest Tools v0.1

Discovered modules: ['sample_module', 'TLSv11_Test', 'TLSv1_Test']
Running all modules...
Running module: sample_module
Module 'sample_module' successfully imported.
Running example module against target: www.integsec.com
Exporting to JSON format...
[
  {
    "target": "www.integsec.com",
    "status": "success",
    "check": "Sample",
    "details": {
      "example": "data"
    }
  }
]
Running module: TLSv11_Test
Module 'TLSv11_Test' successfully imported.
Running TLSv1.1 test against target: www.integsec.com
TLSv1.1 is not supported on www.integsec.com:443
Exporting to JSON format...
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
Running module: TLSv1_Test
Module 'TLSv1_Test' successfully imported.
Running TLSv1 test against target: www.integsec.com
TLSv1 is not supported on www.integsec.com:443
Exporting to JSON format...
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