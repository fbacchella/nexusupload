from sys import exit
from nexuslib.nexusupload import main

def main_wrap():
        exit(main())

if __name__ == "__main__":
    main_wrap()
