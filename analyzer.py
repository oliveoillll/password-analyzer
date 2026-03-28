import re
from collections import Counter
import pandas as pd

# load passwords
def load_passwords(filepath, sample=None):
    passwords = []
    with open(filepath, 'rb') as f:
        for line in f:
            try:
                pw = line.strip().decode('utf-8')
                if pw: 
                    passwords.append(pw) # only add non-empty passwords
            except UnicodeDecodeError:
                continue 
    return passwords[:sample] if sample else passwords # return all passwords if sample is None

# load wordlist
def load_wordlist(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f: # ignore decoding errors in wordlist
        return set(word.strip().lower() for word in f) # load wordlist into a set for O(1) lookups

# templating
CRACKING_SPEED = 60_000_000_000  # MD5 benchmark based on Hashcat performance for an RTX 3060

def get_template(pw):
    template = ''
    for c in pw:
        if c.isupper():
            template += 'U' # uppercase
        elif c.islower():
            template += 'l' # lowercase
        elif c.isdigit():
            template += 'd' # digit
        else:
            template += 's' # symbol
    return re.sub(r'(.)\1+', r'\1+', template)

def get_character_set_size(pw):
    size = 0
    if re.search(r'[a-z]', pw): size += 26 # lowercase letters
    if re.search(r'[A-Z]', pw): size += 26 # uppercase letters
    if re.search(r'\d', pw): size += 10 # digits
    if re.search(r'[^a-zA-Z0-9]', pw): size += 32 # common symbols
    return size if size > 0 else 26

def estimate_crack_time(pw):
    R = get_character_set_size(pw)
    L = len(pw)
    combinations = R ** L # total possible combinations
    seconds = combinations / (2 * CRACKING_SPEED) # divide by 2 for average case
    return seconds

def legacy_compliant(pw):
    has_upper = bool(re.search(r'[A-Z]', pw)) # must have at least one uppercase letter
    has_digit = bool(re.search(r'\d', pw)) # must have at least one digit
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', pw)) # must have at least one symbol
    return len(pw) >= 8 and has_upper and has_digit and has_symbol # true if password is also >8 characters long

def extract_features(pw, wordlist):
    return {
        'password': pw,
        'length': len(pw), 
        'meets_nist_length': len(pw) >= 15, # NIST recommends at least 15 characters for user-generated passwords
        'legacy_compliant': legacy_compliant(pw),
        'in_blocklist': pw.lower() in wordlist, 
        'template': get_template(pw),
        'crack_time_seconds': estimate_crack_time(pw),
    }


def main():
    print("loading passwords")
    passwords = load_passwords('rockyou.txt', sample=10_000)

    print("loading wordlist")
    wordlist = load_wordlist('wordlist.txt')

    print("extracting features")
    records = []
    for pw in passwords:
        records.append(extract_features(pw, wordlist))

    df = pd.DataFrame(records) # dataframe for aggregating and analysis of results

    print("aggregating results")

    # calculate compliance rates and distributions
    nist_compliance_rate = df['meets_nist_length'].mean() * 100 
    legacy_compliance_rate = df['legacy_compliant'].mean() * 100
    blocklist_rate = df['in_blocklist'].mean() * 100
    
    top_templates = df['template'].value_counts().head(10) # most common templates, e.g. 'Ullllllld' for 'Password1'

    def classify_crack_time(seconds):
        if seconds < 60:
            return 'under 1 minute'
        elif seconds < 3600:
            return 'under 1 hour'
        elif seconds < 86400:
            return 'under 24 hours'
        else:
            return 'over 24 hours'

    # classify cracking times into buckets for distribution analysis
    df['crack_time_category'] = df['crack_time_seconds'].apply(classify_crack_time)
    crack_time_dist = df['crack_time_category'].value_counts(normalize=True) * 100

    print("\nNIST Compliance:")
    print(f"Meets 15-char minimum: {nist_compliance_rate:.1f}%")
    print(f"Legacy compliant (8+ chars, upper, digit, symbol): {legacy_compliance_rate:.1f}%")
    print(f"Found in blocklist: {blocklist_rate:.1f}%")

    print("\nTop 10 Password Templates:")
    print(top_templates)

    print("\nCracking Time Distribution:")
    print(crack_time_dist)

    df.to_csv('results.csv', index=False)
    print("\nFull results saved to results.csv")

if __name__ == '__main__':
    main()