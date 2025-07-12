import os
import sys
import argparse
import numpy as np
import pandas as pd
import pickle
import joblib
from datetime import datetime
import logging
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import hashlib
import pefile
import magic
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MalwareDetectionTrainer:
    def __init__(self, data_dir, model_type='random_forest'):
        self.data_dir = data_dir
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_selector = SelectKBest(f_classif, k=100)
        self.feature_names = []
        
    def extract_pe_features(self, file_path):
        """Extract features from PE files"""
        features = {}
        try:
            pe = pefile.PE(file_path)
            
            # Basic PE header features
            features['machine'] = pe.FILE_HEADER.Machine
            features['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
            features['time_date_stamp'] = pe.FILE_HEADER.TimeDateStamp
            features['size_of_optional_header'] = pe.FILE_HEADER.SizeOfOptionalHeader
            features['characteristics'] = pe.FILE_HEADER.Characteristics
            
            # Optional header features
            if hasattr(pe, 'OPTIONAL_HEADER'):
                features['major_linker_version'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
                features['minor_linker_version'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
                features['size_of_code'] = pe.OPTIONAL_HEADER.SizeOfCode
                features['size_of_initialized_data'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
                features['size_of_uninitialized_data'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
                features['address_of_entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                features['base_of_code'] = pe.OPTIONAL_HEADER.BaseOfCode
                features['image_base'] = pe.OPTIONAL_HEADER.ImageBase
                features['section_alignment'] = pe.OPTIONAL_HEADER.SectionAlignment
                features['file_alignment'] = pe.OPTIONAL_HEADER.FileAlignment
                features['major_os_version'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
                features['minor_os_version'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
                features['size_of_image'] = pe.OPTIONAL_HEADER.SizeOfImage
                features['size_of_headers'] = pe.OPTIONAL_HEADER.SizeOfHeaders
                features['checksum'] = pe.OPTIONAL_HEADER.CheckSum
                features['subsystem'] = pe.OPTIONAL_HEADER.Subsystem
                features['dll_characteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            
            # Section features
            section_names = []
            section_sizes = []
            section_entropies = []
            
            for section in pe.sections:
                section_names.append(section.Name.decode('utf-8', errors
