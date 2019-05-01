# AWS Security Review

Just a Python program for dealing with custom security tests of AWS usage, has built-in support for the Center for Internet Security (CIS) benchmarks.

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
