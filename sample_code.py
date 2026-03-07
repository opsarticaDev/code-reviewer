"""Sample Python file for testing CodeReviewer"""


def calculate_fibonacci(n):
    """Calculate the nth Fibonacci number."""
    if n <= 0:
        return 0
    elif n == 1:
        return 1
    else:
        return calculate_fibonacci(n - 1) + calculate_fibonacci(n - 2)


def find_duplicates(items):
    """Find duplicate items in a list."""
    seen = set()
    duplicates = []
    for item in items:
        if item in seen:
            duplicates.append(item)
        seen.add(item)
    return duplicates


# Example usage
if __name__ == "__main__":
    print(f"Fibonacci(10) = {calculate_fibonacci(10)}")
    print(f"Duplicates: {find_duplicates([1, 2, 3, 2, 4, 3, 5])}")
