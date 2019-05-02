# AWS Security Review

Just a Python program for dealing with custom security tests of AWS usage, has built-in support for the Center for Internet Security (CIS) benchmarks.

## Prerequisites

1. Using CloudFormation create an IAM User, IAM Policy, and IAM Role for this tool

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: AWS Security Review App
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: "app-aws-security-review"
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
                - arn:aws:iam::*:role/app-aws-security-review
            Action:
              - sts:AssumeRole
  UserApp:
    Type: AWS::IAM::User
    Properties:
      UserName: aws-security-review
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
      PolicyName: "app-aws-security-review"
      Roles:
        - !Ref AppRole
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Resource: "*"
            Action:
              - report:GenerateCredentialReport
              - report:GetCredentialReport
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

2. install dependancies, tested against python3.7

```bash
pip install -r requirements.txt
```

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

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
