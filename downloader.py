# Malware dataset builder.
import os
import bs4
import sys
import time
import zipfile
import requests
import concurrent.futures

import config

class MalShare:
    """
    Creates an object to handle downloading from MalShare(http://malshare.com/)
    """

    def __init__(self, typeClass, samples):
        """
        :param typeClass: type class to focus on.
        :param samples: number of samples to download.
        """

        self.typeClass = typeClass
        self.path = f"dataset/{self.typeClass}"
        self.samples = samples
        self.download_queue = []
        self.apikey = "c731b8c98c32668d9180319242e2c03df3992e3451ecd9bc61d1c00e16734b74"#INSERT YOUR API KEY
        
    def _queue_download(self):
        """
        Queues MD5 hashes of executables of the malware class specified from MalShare.
        All the hashes are written in a file for further reference.
        """
        print(f"{config.Colours.HEADER}[+] Generating a download sequence for {self.typeClass}.{config.Colours.ENDC}")

        # Create a folder if it doesn't already exist.
        try:
            os.mkdir(self.path)
        except FileExistsError:
            pass
        
        data = []
        # Fetch all search results for the specified class and make a table.
        query_url = "https://malshare.com/search.php?query=" + self.typeClass
        print(f"{config.Colours.INFO}[*] Querying class {self.typeClass}...{config.Colours.ENDC}")
        response = requests.get(query_url)
        print("[~] Parsing results...")
        soup = bs4.BeautifulSoup(response.text, 'html.parser')
        rows = soup.find_all("tr")
        for row in rows:
                cols = row.find_all("td")
                cols = [ele.text.strip() for ele in cols]
                data.append([ele for ele in cols if ele])
        
        # Iterate over all hashes and download the file if it's a PE.
        print(f"[~] Creating download sequence for {self.typeClass}...")

        counter = 0
        for row in data:
            # Check if the row i has less values than needed.
            if len(row) < 2:
                continue
            
            # Check if the row corresponds to a PE.
            if "PE" in row[1]:
                self.download_queue.append(row[0])
                counter += 1
                if counter >= self.samples:
                    break
        # Write to file for further reference.
        with open(f"{self.path}/queue.txt", 'w') as filehandle:
            for entry in self.download_queue:
                filehandle.write('%s\n' % entry)

        print(f"{config.Colours.HEADER}[+] {len(self.download_queue)} files queued to download for {self.typeClass}.{config.Colours.ENDC}")
        return

    def download(self):
        """
        Downloads executables of the malware class specified from MalShare.
        """
        print(f"{config.Colours.INFO}[+] Initiated database build for {self.typeClass}.{config.Colours.ENDC}")
        
        # Check if a reference file for MD5 hashes exists. Initiate queueing sequence if it doesn't exists.
        try:
            with open(f"{self.path}/queue.txt", 'r') as filehandle:
                for line in filehandle:
                    entry = line[:-1]
                    self.download_queue.append(entry)
        except FileNotFoundError:
            self._queue_download()
        
        # Start download from either a reference file or a download queue.
        finally:
            print(f"{config.Colours.INFO}[*] Beginning download sequence for {self.typeClass}.{config.Colours.ENDC}")
            for idx, entry in enumerate(self.download_queue):
                
                # Check if the file already exists.
                if os.path.isfile(f"{self.path}/{entry}"):
                    continue 

                print(f"[~] Downloading {self.typeClass}({idx+1}/{self.samples}): {entry}")
                path = f"{self.path}/{entry}" 
                r = requests.get(f"https://malshare.com/api.php?api_key={self.apikey}&action=getfile&hash={entry}")
                print(open(path, "wb").write(r.content))
                if idx >= self.samples:
                    break
            
        print(f"{config.Colours.SUCCESS}[+] Downloading process for {self.typeClass} complete.{config.Colours.ENDC}")
        return

def BuildDatabase(samples):
    """
    Download all the files to build a local database.

    :param samples: number of samples to download per class.
    """

    print(f"{config.Colours.HEADER}[+] Initiated database build.{config.Colours.ENDC}")
    try:
        os.mkdir("dataset")
    except FileExistsError:
        pass

    objects = {}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers = len(config.Classes))
    for typeClass in config.Classes:
        objects[typeClass] = MalShare(typeClass, samples) # Pass the number of samples to download for the particular class.
        try:
            executor.submit(objects[typeClass].download)
            print(f"[+] Thread started for {typeClass}.")
        except:
            print(f"{config.Colours.ERROR}[!] Unable to start thread for {typeClass}.{config.Colours.ENDC}")
    
    executor.shutdown(wait=True)
    print(f"{config.Colours.SUCCESS}[+] Dataset build complete.{config.Colours.ENDC}")
    return

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("usage: python predict.py <number_of_samples_per_class>")
        exit()

    # Simply build the database throught queuing and downloading if this file is run individually.
    BuildDatabase(int(sys.argv[1]))

# To get PE from Zip files.

# if row[1] == "Zip":
#     print("[+] Downloading " + row[0])

#     path = f"dataset/{typeClass}/{row[0]}" 
#     r = requests.get(f"https://malshare.com/api.php?api_key={malshare_apikey}&action=getfile&hash={row[0]}")
#     print(open(path + ".zip", "wb").write(r.content))

#     # Unzip the file and remove the zip.
#     with zipfile.ZipFile(f"{path}.zip","r") as zip_ref:
#         zip_ref.extractall(path, pwd=b"infected")
#     os.remove(path + ".zip")
