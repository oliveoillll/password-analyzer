# password-analyzer
Identifies passwords from the RockYou databreach and compares them to NIST guidelines

## Overview

This project analyzes a cleaned 14-million-password of the 2009 RockYou data breach. It evaluates real-world user behavior against legacy password complexity rules and the modern 2024 NIST SP 800-63B guidelines. The program calculates mathematical entropy, maps structural patterns, checks passwords against blocklists, and estimates brute force cracking times based on modern GPU benchmarks. 

This analysis maps the observed vulnerabilities to MITRE ATT&CK Technique T1110 (Brute Force).



## Project Structure

* `analyzer.py`: The main execution script. Parses the dataset, extracts features, makes calculations, and outputs the results.

* `entropy.py`: Contains the entropy calculation logic. This is an imported module used by `analyzer.py`.

* `downloadWordlist.py`: Pulls dictionary words from the NLTK library and custom RockYou terms to build the reference blocklist.

* `graphs.py`: Reads the CSV output from the analyzer and generates graphical distributions.
  
* `rockyou.txt.zip`: The compressed raw dataset.


## Prerequisites

* Python 3.12 (or higher)

## Installation & Setup

1. **Clone the repository:**

   ```bash

   git clone [https://github.com/oliveoillll/password-analyzer.git](https://github.com/oliveoillll/password-analyzer.git)

   cd password-analyzer

2. **Install dependencies:**

```pip install -r requirements.txt```

3. **Run the analysis:** 

```unzip rockyou.txt.zip into the directory```

```run analyzer.py```
