import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import re

df = pd.read_csv("results.csv")

#Bar graph for crack time
plt.figure()
crackTime_count = df['crack_time_category'].value_counts(normalize=True) * 100
crackTime_count.plot(kind='bar')

for i in range(len(crackTime_count)):
    plt.text(i, crackTime_count.iloc[i], f'{crackTime_count.iloc[i]:.1f}%', ha='center', va='bottom')

plt.title("Password Cracking Time Duration")
plt.xlabel("Time to Crack")
plt.ylabel("% Percentage of Passwords")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("crack_time_distribution.png")

plt.show()


#Bar graph for character breakdown
char_breakdown = {
    'Has Uppercase': df['password'].apply(lambda pw: bool(re.search(r'[A-Z]', pw))).mean() * 100,
    'Has Digit':    df['password'].apply(lambda pw: bool(re.search(r'\d', pw))).mean() * 100,
    'Has Symbol':    df['password'].apply(lambda pw: bool(re.search(r'[^a-zA-Z0-9]', pw))).mean() * 100,
    '8+ chars':      (df['password'].apply(lambda pw: len(pw) >= 8).mean() * 100),
    'Has all three': df['password'].apply(lambda pw: bool(re.search(r'[A-Z]', pw)) and bool(re.search(r'\d', pw)) and bool(re.search(r'[^a-zA-Z0-9]', pw))).mean() * 100
}

plt.figure()

ax =  pd.Series(char_breakdown).plot(kind='bar')

for bar in ax.patches:
    ax.annotate(f'{bar.get_height():.1f}%', 
        xy=(bar.get_x() + bar.get_width() /2, bar.get_height()), 
        ha='center', va='bottom')

plt.title("Character Class Breakdown")
plt.xlabel("Type")
plt.ylabel("% Percentage of Characters")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("passw_types.png")

plt.show()


#Bar graph for compliance rates and distributions
compRate_and_distrib = {
    'Meets NIST Length': df['meets_nist_length'].mean() * 100, 
    'Legacy compliant': df['legacy_compliant'].mean() * 100,
    'In blocklist': df['in_blocklist'].mean() * 100,
}

plt.figure()

ax_cd = pd.Series(compRate_and_distrib).plot(kind='bar')

for cd_bar in ax_cd .patches:
    ax_cd .annotate(f'{cd_bar.get_height():.1f}%', 
        xy=(cd_bar.get_x() + cd_bar.get_width() /2, cd_bar.get_height()), 
        ha='center', va='bottom') 
plt.title("Calculate Compliance Rates and Distributions")
plt.xlabel("Type")
plt.ylabel("% Percentage")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("compliance_and_distributions.png")

plt.show()

