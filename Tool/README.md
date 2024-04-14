# EquivGuard

EquivGuard utilizes taint analysis to identify potential vulnerability patterns, combined with symbolic execution to verify path reachability.
## Dependencies Installation

### [virtualenv](https://virtualenvwrapper.readthedocs.io/en/latest/) for configuring the Python environment.

```bash
$ pip3 install virtualenvwrapper
$ source /usr/local/bin/virtualenvwrapper.sh
$ mkvirtualenv --python=`which python3.8` python38
```

### solc-select
```bash
$ pip3 install solc-select
```

### [z3](https://github.com/Z3Prover/z3/releases) Theorem Prover version 4.5.0.

Download the [source code of version z3-4.5.0](https://github.com/Z3Prover/z3/releases/tag/z3-4.5.0)

Install z3 using Python bindings

```bash
$ python3 scripts/mk_make.py --python
$ cd build
$ make
$ sudo make install
```

### Tool Installation
Run the following script to install the tools:
```bash
$ bash install.sh
```

## How to Run EquivGuard

Run ```python3 EquivGuard.py -h``` to view a list of options.

```plaintext
oooooooooooo                         o8o                .oooooo.                                         .o8  
`888'     `8                         `"'               d8P'  `Y8b                                       "888  
 888          .ooooo oo oooo  oooo  oooo  oooo    ooo 888           oooo  oooo   .oooo.   oooo d8b  .oooo888  
 888oooo8    d88' `888  `888  `888  `888   `88.  .8'  888           `888  `888  `P  )88b  `888""8P d88' `888  
 888    "    888   888   888   888   888    `88..8'   888     ooooo  888   888   .oP"888   888     888   888  
 888       o 888   888   888   888   888     `888'    `88.    .88'   888   888  d8(  888   888     888   888  
o888ooooood8 `V8bod888   `V88V"V8P' o888o     `8'      `Y8bood8P'    `V88V"V8P' `Y888""8o d888b    `Y8bod88P" 
                   888.                                                                                       
                   8P'                                                                                        
                   "    
                                                                          
usage: EquivGuard.py [-h] [--solidity-file] [--vuln-type VULN_TYPE] [--timeout TIMEOUT] [--target_function TARGET_FUNCTION] [--target_contract TARGET_CONTRACT] file

Vulnerability detection tool for EVM Inequivalent Defects

positional arguments:
  file                  File to analyze

optional arguments:
  -h, --help            show this help message and exit
  --solidity-file, -s   Use this option when the file is a Solidity file instead of EVM bytecode hex string. By default, it is unset
  --vuln-type VULN_TYPE, -vt VULN_TYPE
                        The type of vulnerability to analyze.
  --timeout TIMEOUT, -t TIMEOUT
                        Timeout for Z3 Solver. Default = 300
  --target_function TARGET_FUNCTION, -tf TARGET_FUNCTION
                        The target function to analyze
  --target_contract TARGET_CONTRACT, -tc TARGET_CONTRACT
                        The target contract to analyze
```

```plaintext
# To analyze contracts within an entire file
python EquivGuard.py -s <filename> -vt CCRA
python EquivGuard.py -s input/example/vul_CCRA.sol -vt CCRA
```
