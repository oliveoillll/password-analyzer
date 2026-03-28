# also pip install nltk. this is just a setup script for english words + relevant words for rockyou

import nltk
nltk.download('words')
from nltk.corpus import words

wordlist = set(w.lower() for w in words.words())
wordlist.update({'rockyou', 'facebook', 'myspace', 'friendster', 'password', 'admin'})

with open('wordlist.txt', 'w') as f:
    for word in sorted(wordlist):
        f.write(word + '\n')

print(f"Wordlist saved with {len(wordlist)} words")
