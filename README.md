# Introduction

# Explaining the Algorithm

## PRBG

## RSA

# Runing the program

## Before Running the Program
There are some libraries that need to be installed to run this project
```
pip install cryptography            # used for cryptography algorithms
pip install sympy                   # contains some useful modular arithmetic functions
sudo apt-get install libgmp-dev     # C library used for big numbers
```

## How to run the program

#### C
```
./randgen <password> <confusion_string> <iteration_count> > <destination_file>
```

```
./rsagen -c <password> <confusion_string> <iteration_count>
./rsagen -f < <input_file>
```

#### Python

```
python3 randgen.py <password> <confusion_string> <iteration_count> > <destination_file>
```

```
python3 rsagen.py -c <password> <confusion_string> <iteration_count>
python3 rsagen -f < <input_file>
```