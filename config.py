# ANSI colour codes for terminal.
class Colours:
    HEADER = "\033[36m"
    INFO = "\033[34m"
    SUCCESS = "\033[91m"
    WARNING = "\033[33m"
    ERROR = "\033[31m"
    ENDC = "\033[00m"

# Classes to train for and predict against.
Classes = [
    "backdoor",
    "worm",
    "trojan",
    # "rootkit",
    # "virus",
    # "bot",
    # "ransomware",
    # "adware",
    # "downloader",
    # "benign" # commented because this list is used to download malwares from online data stores.
]
