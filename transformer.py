import os
import io
import json
import features

class InvalidPEFileInputError(Exception):
    """
    Invalid input to the constructor.
    """
    pass

class InvalidArgError(Exception):
    """
    When no argument is passed.
    """
    pass   

class PETransformer(object):
    """
    Accepts PE file paths/bytes/file objects.

    1. first arg -> File Path OR File Bytes OR File Object (FileStream)
    2. Get bytes from the file.
    3. Generate features from PEFeatureExtractor

    :class_variable np.array feature_vector: Feature Vector to be used for computation
    :class_variable dict raw_features: raw_features from which the feature_vector is computed

    Usage:
        file_path = 'sample.exe'
        transformer = PETransformer(file_path)
        transformer.vector # Feature Vector for computations
        transformer.serialize # Dumpable feature string
    """

    extractor = features.PEFeatureExtractor()

    def _get_bytes_from_bytes(self, bytes):
        return bytes

    def _get_bytes_from_pe_path(self, path):
        with open(path, "rb") as pe:
            data = pe.read()
        return data

    def _get_bytes_from_pe_file(self, file):
        data = file.read()

        return data

    _get_bytes_strategies = {
        "bytes": _get_bytes_from_bytes,  
        "path": _get_bytes_from_pe_path,
        "file": _get_bytes_from_pe_file
    } # Byte Extraction Strategies
    
    @staticmethod
    def _set_arg_type(arg):
        if type(arg) == bytes:
            return "bytes"
        elif isinstance(arg, io.IOBase):
            return "file"
        elif os.path.exists(arg):
            return "path"  

    def __init__(self, *args, **kwargs):
        """
        Check if raw_features are inputted,
        determine input type,
        get bytes for the pe,
        set the features

        :param np.array feature_vector: numpy array feature vector
        :param dict raw_features: raw features which can be serializedss 

        Use kwarg -> raw_features to directly load via raw_features string.
        """

        raw_features = kwargs.get("raw_features")
        if raw_features is not None:
            self._set_features_via_raw_features_string(raw_features)
            return
        else:
            self.feature_vector = None
            self.raw_features = None

        try:
            pe_arg = args[0] # First Arg is either one of the three types.
        except:
            raise InvalidArgError()

        arg_type = self._set_arg_type(pe_arg)
        try:
            self.bytes = self._get_bytes_strategies[arg_type](self, pe_arg)
        except:
            raise InvalidPEFileInputError()

        self._set_features()

    def _set_features_via_raw_features_string(self, raw_features):
        """
        Set via serialize raw_feature_dict.
        """
        self.raw_features = json.loads(raw_features)
        self.feature_vector = self.extractor.process_raw_features(self.raw_features)

    def _set_features(self):
        """
        Set feature_vector vector and raw_features dict. 
        """

        self.raw_features = self.extractor.raw_features(self.bytes)
        self.feature_vector = self.extractor.process_raw_features(self.raw_features)

    @property
    def vector(self):
        return self.feature_vector
    
    @property
    def feature_dict(self):
        return self.raw_features

    @property
    def serialize(self):
        return json.dumps(self.raw_features)