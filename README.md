# 22WSD516 Telectommunication Network Security Lab Experiment

### Pre-requisites:
- Python 3.9
- [aes v1.2.0](https://pypi.org/project/aes/)

### Files:
- `Task1.py`
- `Task2.py`
- `Task3.py`
- `fun_padding_oracle.py`

---
## Setup
Within your Python environment, run the command `pip install -r requirements.txt` to install all required libraries 
## Usage
Each script can be run by itself using the command `python3 <SCRIPT NAME>.py`
### Task 1 - AES Validation
The code within this script instantiates a simple AES-128 ECB cipher. Due to the relative simplicity of the task, no functions were implemented that would benefit from the use of a boilerplate.

`python ./Task1.py`
### Task 2 - CBC Implementation
This script implements an AES-128 CBC Cipher as a wrapper class around the ECB implementation tested in Task 1. 
The class has been implemented in a way that allows it to be imported by other scripts, validation functionality being contained within a boilerplate.

`python ./Task2.py` or `from Task2 import CBC_AES`
### Padding Oracle
This script implements an oracle function for use within the padded oracle attack, mimicking that provided in Matlab
Additional verification code is contained within the boilerplate, checking 4 test cases

`python ./fun_padding_oracle.py` or `from fun_padding_oracle import fun_padding_oracle`
### Task 3 - Padded Oracle Attack
This script implements the padded oracle attack as a function which takes in 2 consecutive blocks of ciphertext and returns the plaintext block
As with previous scripts, the main task is implemented within the boilerplate, optimising the code for re-use in other scripts.

`python ./Task3.py` or `from Task3 import padded_attack`