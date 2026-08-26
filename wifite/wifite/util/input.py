#!/usr/bin/env python
# -*- coding: utf-8 -*-
from _pyrepl.readline import raw_input

# Fix for raw_input on python3: https://stackoverflow.com/a/7321970
try:
    input = raw_input
except NameError:
    pass