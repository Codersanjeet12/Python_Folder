# Program 5: Frequency of Each Character
string = input("Enter a string: ")
freq = {}

for ch in string:
    freq[ch] = freq.get(ch, 0) + 1

for ch, count in freq.items():
    print(f"{ch}: {count}")
