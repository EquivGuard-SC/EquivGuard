#!/bin/bash
wrokon python38
pip install -r requirement.txt
cd ./solidity/EquivGuard_slither
python setup.py install