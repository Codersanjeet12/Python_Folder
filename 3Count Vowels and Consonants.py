# Program 3: Count Vowels and Consonants
string = input("Enter a string: ").lower()
vowels = "aeiou"
v_count = c_count = 0

for ch in string:
    if ch.isalpha():
        if ch in vowels:
            v_count += 1
        else:
            c_count += 1

print("Vowels:", v_count)
print("Consonants:", c_count)
