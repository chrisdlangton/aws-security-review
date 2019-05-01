import os
from yaml import load
#TODO: put this in libs

CONFIG_PATH = os.path.realpath(
    os.path.join(os.getcwd(), 'rules.yaml')) #TODO: make this an argument
rules = None
with open(CONFIG_PATH, 'r') as f:
    rules = load(f)
