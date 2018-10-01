import os
from yaml import load, dump


CONFIG_PATH = os.path.realpath(
    os.path.join(os.getcwd(), 'config.yaml'))
config = None
with open(CONFIG_PATH, 'r') as f:
  config = load(f)
