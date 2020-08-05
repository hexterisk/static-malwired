# Static Malwired
Classifies if a PE is benign or a malware, based on static analysis.
The given PE can be classified among the classes defined in the config file. The user must modify the classes based on the dataset and the requirement. Simply edit the classes in [config.py](https://github.com/hexterisk/static-malwired/blob/master/config.py) and the model in [train.py](https://github.com/hexterisk/static-malwired/blob/master/train.py) as per requirement. The POC in the [IPython notebook](https://github.com/hexterisk/static-malwired/blob/master/Model%20POC.ipynb) has been run on a much smaller dataset. The model gives a 93% accuracy on a dataset of decent size.

Also checkout the [repository](https://github.com/hexterisk/dynamic-malwired/) hosting the POC for a classifier working on dynamic analysis.

DISCLAIMER: The whole suite has been created, although the user would have to acquire the dataset and train the model by themselves.

## Algorithm

A [blog-post](https://hexterisk.github.io/blog/posts/2020/07/20/classification-of-malwares-through-static-analysis/) on the features used in this POC.
Apart from the usual (and unreliable) static information from headers in the PE file format, the major part is the use of raw bytes with the following algorithm.

* Create shingles out of the binary data from executables.
Take a bunch of consecutive words(ideally 3) from the data and hash them into integers. This retains a little more of the structure of the data than simply hashing words individually. Each unique hash string is called a shingle.

* Calculate MinHash of each shingle.
MinHash signatures can be used to approximate the Jaccard similiarity between any two sets, and it's faster than simply calculating the union or intersection of two large sets since the signatures are much shorter than the sets(shingles in this case) itself. It works because it can be proven that MinHash similarity is equal to the Jaccard similarity. Read more [here](https://mccormickml.com/2015/06/12/minhash-tutorial-with-python-code/).

* Implement Locality Sensitive Hashing over these hashes.
The MinHash computation is an O(n) algorithm. LSH can be used to bring this down to a sub-linear cost. The algorithm ensures that sets with higher Jaccard similarity always have higher probability to get returned than the sets with lower similarities. Read about the algorithm [here](http://infolab.stanford.edu/~ullman/mmds/ch3.pdf).

## Code Base

The dataset for malware analysis was formed from the database of [MalShare](https://malshare.com).

DISCLAIMER: The dataset built from MalShare is in no way adequate. Kindly find other source for the database. The dataset I used was confidential and I cannot disclose it. Therefore, I've only mentioned and released the code containing the open source site I used. Pull requests towards any similar sources would be appreciated. The script [downloader.py](https://github.com/hexterisk/static-malwired/blob/master/downloader.py) can be modified to include classes for different sources.

### Flow:

1. Run [downloader.py](https://github.com/hexterisk/static-malwired/blob/master/downloader.py) to download the malware database. Add more classes for processing data from more websites, or simply skip this step if you already have a database and don't need to download anything.
Make sure the directory structure for the dataset folder is as follows:
```bash
static-malwired/
├── dataset/
│   ├── classA
│   │   ├── exeA
│   │   ├── exeB
│   │   .
│   │   .
│   │   .
│   │   └── exeZ
│   ├── classB
│   │   ├── exeA
│   │   .
│   │   └── exeZ
│   ├── classC
│   │   ├── exeA
│   │   .
│   │   └── exeZ
.   .
.   .
.   .
│   └── classZ
├── app.py
├── builder.py
.
.
.
└── transformer.py
```

2. Run [builder.py](https://github.com/hexterisk/static-malwired/blob/master/builder.py) to build the dataset from the downloaded database.

3. Run [train.py](https://github.com/hexterisk/static-malwired/blob/master/train.py) to train a model.

4. Run [predict.py](https://github.com/hexterisk/static-malwired/blob/master/predict.py) to predict a sample's type. Provide the path to the file to be classified and the path to the trained model as command-line arguments, in the same order.

### Components:

[app.py](https://github.com/hexterisk/static-malwired/blob/master/app.py): Flask RESTful API on which the project has been deployed.

[builder.py](https://github.com/hexterisk/static-malwired/blob/master/builder.py): Builds the dataset from all the files in the database.

[config.py](https://github.com/hexterisk/static-malwired/blob/master/config.py): Contains malware classes list that can be deleted as per requirement.

[downloader.py](https://github.com/hexterisk/static-malwired/blob/master/downloader.py): Script that scrapes pages of MalShare and downloads PEs from their database using their API.

[features.py](https://github.com/hexterisk/static-malwired/blob/master/features.py): Feature extraction script from the files in the dataset. Original script taken from the ember project and modified to apply various tweaks for multiclass classification and file specific signatures.

[predict.py](https://github.com/hexterisk/static-malwired/blob/master/predict.py): A python script to predict a PE's class using a trained model.

[recomposer.py](https://github.com/hexterisk/static-malwired/blob/master/recomposer.py): Script to recompose a file's header, section names and inject random data to revamp a file. Provided to facilitate dataset augmentation. Shall be used if general file information features like Headers and Sections are used.

[train.py](https://github.com/hexterisk/static-malwired/blob/master/train.py): A python script to train the model, given the data.

[transformer.py](https://github.com/hexterisk/static-malwired/blob/master/transformer.py): Transform the given files into vectorized features.