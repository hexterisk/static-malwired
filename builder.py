import os
import sys
import json
import transformer
import concurrent.futures

import config

def Builder(typeClass):
    """
    Iterates over all samples and dumps raw features into a json file.
    
    :param typeClass: type class to focus on.
    """
    print(f"{config.Colours.INFO}[*] Building dataset for {typeClass}.{config.Colours.ENDC}")
    
    # Set the path and clear typeClass' download queues and json dump.
    path = f"dataset/{typeClass}"
    try:
        os.remove(f"{path}/dump.json")
        os.remove(f"{path}/queue.txt")
    except FileNotFoundError:
        pass
    
    # Use PETransformer to fetch feature vectors for a given PE and dump into typeClass' local folder.
    with open(f"{path}/dump.json", 'w') as buildFile:
        for sample in os.listdir(path):
            print(f"[~] Building {path}/{sample}")
            transformed = transformer.PETransformer(f"{path}/{sample}")                
            data_dict = transformed.feature_dict
            buildFile.write(json.dumps(data_dict))
            buildFile.write('\n')
    
    print(f"{config.Colours.SUCCESS}[+] Dataset build for {typeClass} complete.{config.Colours.ENDC}")
    return

def Reader():
    """
    Reads the dump files for all classes and returns a feature vector dictionary.
    as a dictionary of lists.
    """
    print(f"{config.Colours.HEADER}[+] Initiated dataset read.{config.Colours.ENDC}")
    
    # Iterate over all classes.
    data = {}
    for typeClass in config.Classes:
        print(f"{config.Colours.INFO}[*] Reading dataset for {typeClass}.{config.Colours.ENDC}")
        
        # Load typeClass' json dump into memory and append to a dictionary.
        path = f"dataset/{typeClass}/dump.json"
        data[typeClass] = []
        try:
            with open(path, 'r') as buildFile:
                lines = [line.strip() for line in buildFile.readlines()]
            for line in lines:
                data[typeClass].append(transformer.PETransformer(raw_features=line).vector)
        except FileNotFoundError:
            print(f"{config.Colours.ERROR}[!] Dump file not found for {typeClass}!{config.Colours.ENDC}")
            return
        print(f"{config.Colours.SUCCESS}[+] Dataset fetch for {typeClass} complete.{config.Colours.ENDC}")

    print(f"{config.Colours.SUCCESS}[+] Dataset loading complete.{config.Colours.ENDC}")
    return data

def Build_Dataset():
    """
    Download all the files in a multi-threaded implementation to build a local database.
    """
    print(f"{config.Colours.HEADER}[+] Initiated dataset build.{config.Colours.ENDC}")

    # Multi threaded building process for json dumps.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers = len(config.Classes))
    for typeClass in config.Classes:
        try:
            executor.submit(Builder, typeClass)
            print(f"[+] Thread started for {typeClass}.")
        except:
            print(f"{config.Colours.ERROR}[!] Unable to start thread for {typeClass}.{config.Colours.ENDC}")
    
    # Shutdown the thread manager during exit.
    executor.shutdown(wait=True)
    print(f"{config.Colours.SUCCESS}[+] Dataset build complete.{config.Colours.ENDC}")
    return

if __name__ == "__main__":
    # Simply build the dataset when this file is run individually.
    Build_Dataset()
