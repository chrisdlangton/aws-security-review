# Reconnoitre - AWS Security Review utility

Just a Python program for dealing with custom security tests of AWS usage, has built-in support for the Center for Internet Security (CIS) benchmarks.

## Prerequisites

1. Using CloudFormation create an IAM User, IAM Policy, and IAM Role for this tool

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: Reconnoitre - AWS Security Review App
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: "app-reconnoitre"
      Path: "/"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: "Allow"
            Principal:
              AWS:
                - "{your aws account number}"
            Action:
              - "sts:AssumeRole"
  AssumeAppRole:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Resource:
                - arn:aws:iam::*:role/app-reconnoitre
            Action:
              - sts:AssumeRole
  UserApp:
    Type: AWS::IAM::User
    Properties:
      UserName: reconnoitre
      ManagedPolicyArns:
        - !Ref AssumeAppRole
  UserAppAccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName:
        Ref: UserApp
  AppPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: "app-reconnoitre"
      Roles:
        - !Ref AppRole
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Resource: "*"
            Action:
              - iam:GenerateCredentialReport
              - iam:Get*
              - iam:List*
              - cloudtrail:Describe*
              - config:Describe*
              - ec2:Describe*
              - vpc:Describe*
Outputs:
  AccessKey:
    Value:
      Ref: UserAppAccessKey
  SecretKey:
    Value:
      Fn::GetAtt: ["UserAppAccessKey", "SecretAccessKey"]
```

## Installation

1. clone this repo

2. install dependencies, tested against python3.7

```bash
pip install -r requirements.txt
```

3. create a `config.yaml` fromt he example provided

## Usage

Configure your own `config.yaml` based on the example then run the main project file;

```bash
python src/main.py
```

Check out the cli arguments by adding `--help`

## Development

Dev helper scripts make use of docker-ce (go ahead and update these for more general purpose use)

```bash
./build.sh
./test.sh src/main.py -vvvv --debug
```

## Roadmap

1. Complete CIS Benchmark for AWS

2. Output format [STIX](https://github.com/stixproject/python-stix)

3. Send findings to [AWS SecurityHub](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-providers.html#securityhub-custom-providers)

4. Output format [CVRF](https://www.icasi.org/cvrf/)

5. Refactor codebase to use recommended controls for auto-remediation actions, where available.

6. Maybe support risk vuln aggregators that don't themselves support standardards (STIX or CVRF), hopefully they start caring about standards before I get to this

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
