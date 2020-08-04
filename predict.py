import os
import sys
import numpy as np
import lightgbm as lgb

import config
import transformer

def Prediction(peFile, mdlFile):
    """
    Predicts the class of the PE file passed to it.

    :param peFile: PE file to be predicted.
    :param mdlFile: path to trained model.
    """

    if not os.path.exists(mdlFile):
        print(f"{config.Colours.ERROR}[!] Trained model not found. Exiting.{config.Colours.ENDC}")
        exit()

    predictor = lgb.Booster(model_file = mdlFile)    
    # Fetch the feature vector for the PE.
    transformed = transformer.PETransformer(peFile).vector
    # Make prediction for the PE.
    preds = predictor.predict(transformed.reshape(1, 2152))
    # Gives the maximum value out of all the predicted labels.
    return config.Classes[np.argmax(preds)]

if __name__ == "__main__":
    
    if len(sys.argv) < 3:
        print("usage: python predict.py <pe_file> <model_file>")
        exit()

    peFile = sys.argv[1]
    try:
        with open(peFile, "rb") as byte_file:
            pe = byte_file.read()
    except:
        print(f"{config.Colours.ERROR}[!] Error reading file. Exiting.{config.Colours.ENDC}")
        exit()

    predictor = lgb.Booster(model_file=sys.argv[2])    
    # Fetch the feature vector for the PE.
    transformed = transformer.PETransformer(pe).vector
    # Make prediction for the PE.
    preds = predictor.predict(transformed.reshape(1, 2152))
    # Gives the maximum value out of all the predicted labels.
    print(config.Classes[np.argmax(preds)])