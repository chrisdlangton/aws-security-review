import os
from yaml import load


CONFIG_PATH = os.path.realpath(
    os.path.join(os.getcwd(), 'rules.yaml'))
rules = None
with open(CONFIG_PATH, 'r') as f:
  rules = load(f)
