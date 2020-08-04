import numpy as np
import pandas as pd
import lightgbm as lgb
import sklearn.model_selection

import config
import builder

if __name__ == "__main__":

    # Setup dataset for training.
    X = []
    Y = []
    dataset = builder.Reader()
    # Iterate over dataset through all specified classes.
    for typeClass in config.Classes:
        X += dataset[typeClass]
        # Append labels for all the elements fetched in the given class.
        for i in range(len(dataset[typeClass])):
            Y.append(list(dataset.keys()).index(typeClass))

    Data = np.array(X, dtype=np.float32)
    Labels = np.asarray(Y, dtype=np.float32)
    print("Shape of data: ", Data.shape)
    print("Shape of labels: ", Labels.shape)

    X = pd.DataFrame(Data)
    Y = pd.DataFrame(Labels)
    DATA = pd.concat([X, Y], axis = 1)
    Y = DATA.iloc[:, -1]
    X = DATA.iloc[:, :-1]
    x_train, x_test, y_train, y_test = sklearn.model_selection.train_test_split(X, Y, test_size = 0.2, random_state = 42)
    
    print("Number of samples for training:", np.shape(x_train)[0])
    print("Number of samples for testing:", np.shape(x_test)[0])
    print("Number of features for each sample:", np.shape(x_train)[1])

    # Create the model.
    params = {}
    params["learning_rate"] = 0.05
    params["boosting_type"] = "gbdt"
    params["objective"] = "multiclass"
    params["num_class"] = len(config.Classes)
    params["metric"] = "multi_logloss"
    params["sub_feature"] = 0.3
    params["num_leaves"] = 15
    params["min_data"] = 95
    params["max_depth"] = 15
    params["device"] = "cpu"
    d_train = lgb.Dataset(x_train, label = y_train)
    clf = lgb.train(params, d_train, 100)
    clf.save_model("model.mdl")

    print(f"{config.Colours.SUCCESS}[+] Model successfully trained. Saved in file 'model.mdl'. Kindly run 'predict.py' to start using the mdoel.{config.Colours.ENDC}")