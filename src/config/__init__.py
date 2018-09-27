from yaml import load, dump

config = None
with open('config.yaml', 'r') as f:
  config = load(f)
