# Secronix - A Hybrid Secure Code Analyzer for PHP 

## Descriptiom
Secronix is an experimental version of an automated secure code analyzer to identify, assess and remediate the security vulnerabilities throughout the development phase. It uses DAST (Dynamic Application Testing) and SAST (Static Application Security Testing ) to capture the vulnerable source in the run-time environment. In the initial phase of analysis, it performs the attack and audit based analysis on the application by sending a massive amount of malicious requests to force the server side script crash into the errors. Then using the patterns to detect the information leakage in the form of errors or source code in the response data, Secronix develops the dynamic detecotor patterns to locate the vulnerable source. 

## Setup
Copy the secornix folder into your website. You can simply plug the secronix by wrapping the website source code code with following two lines 

```
include "secronix/analyzer.php";  // Insert at first line 

// Your Website Source code here 

$analysis->start_dynamincAnalysis();  // Insert at the last line 

```  

You can plug this into your bootstrap or header and footer file to avoid adding these lines on the every single file in your code base. 
