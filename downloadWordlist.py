# also pip install nltk. this is the blocklist of common english words

import nltk
nltk.download('words')
from nltk.corpus import words

wordlist = set(w.lower() for w in words.words())
wordlist.update({'rockyou', 'facebook', 'myspace', 'friendster', 'password', 'admin'})

with open('wordlist.txt', 'w') as f:
    for word in sorted(wordlist):
        f.write(word + '\n')

print(f"Wordlist saved with {len(wordlist)} words")
