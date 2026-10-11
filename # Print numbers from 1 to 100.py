# Print numbers from 1 to 100for num in range(1, 101):
    print(num)
text = "Data Science"
vowels = "aeiouAEIOU"

count = sum(1 for char in text if char in vowels)

print("Number of vowels:", count)

# Sample customer orders
orders = {
    "Customer1": 8500,
    "Customer2": 12000,
    "Customer3": 9500,
    "Customer4": 15000
}

# Find the first customer with order > 10000
for customer, amount in orders.items():
    if amount > 10000:
        print("First customer with order > 10000 is:", customer, "with amount:", amount)
        break
print("All customers with orders > 10000:")
for customer, amount in orders.items():
    if amount > 10000:
        print(customer, "with amount:", amount) 


        # Customer orders dataset
orders = {
    "Rahul": 12000,
    "Sanjeet": -500,     # Invalid (negative)
    "Shivam": None,      # Invalid (missing)
    "Shiva": 8000,
    "Janum": 0           # Invalid (zero)
}
###

# Detect invalid orders
for customer, amount in orders.items():
    if amount is None or amount <= 0:
        print("Invalid order from:", customer, "->", amount)
    else:
        print("Valid order from:", customer, "->", amount)
