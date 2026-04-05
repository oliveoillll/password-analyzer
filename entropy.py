#Check entropy of passwords
#This help recognize how predictable/unpredictable passwords were used
#The more complex the harder it is to brute force the password


import pandas as pd
import numpy as np
import re

def get_charset(pw):
 
    #Calculate the passwords charset size
    size = 0
    if re.search(r'[a-z]', pw):
        size += 26
    if re.search(r'[A-Z]', pw):
        size += 26
    if re.search(r'[0-9]', pw):
        size  += 10
    if re.search(r'[^a-zA-Z0-9]', pw):
       size  += 32
    return size

def entropy_analyzer(df):
    #Analyze entropy and categorize password strength

    #Convert passwords to string
    df['password'] = df['password'].astype(str)

    #Calculate password length
    df['length'] = df['password'].str.len()

    #Get password range
    df['range'] = df['password'].apply(get_charset)

    df = df[df['range'] > 0]


    #Calculate entropy
    df['entropy'] = df['length'] * np.log2(df['range'])

    #Get passwords category by strength
    df['entropy_category'] = df['entropy'].apply(entropy_check)

    return df

def entropy_check(entropy):   
    #Password strength based on entropy
    if entropy  >= 100:
        return 'Very Strong'
    elif entropy >= 75:
        return 'Strong'
    elif entropy >= 72:
        return 'Fine'
    else:
        return 'Weak'
