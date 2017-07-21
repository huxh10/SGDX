#!/bin/bash

python xbgp-prio.py -d --speedup 1 localhost 6000 xrs update-input.txt 5 0 --processes 1
