# Introduction

# Explaining the Algorithm

## PRBG

## RSA

# Runing the program

## Before Running the Program
There are some libraries that need to be installed to run this project
```
pip install cryptography    # used for cryptography algorithms
pip install sympy           # contains some useful modular arithmetic functions
```

## How to run the program

#### C
```
./randgen <password> <confusion_string> <iteration_count>
```

```
./rsagen <password> <confusion_string> <iteration_count>
```

#### Python

```
python3 randgen.py <password> <confusion_string> <iteration_count>
```

```
python3 rsagen.py <password> <confusion_string> <iteration_count>
```