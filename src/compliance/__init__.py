from yaml import load, dump


rules = None
with open('rules.yaml', 'r') as f:
  rules = load(f)