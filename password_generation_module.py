import string
import secrets
import re
import zxcvbn

def get_word_list():
    # Load a word list from a file or define it directly
    # For simplicity, we can use a small sample list here
    return [
        "apple", "banana", "cherry", "date", "elderberry",
        "fig", "grape", "honeydew", "kiwi", "lemon",
        "mango", "nectarine", "orange", "papaya", "quince",
        "raspberry", "strawberry", "tangerine", "ugli", "vanilla",
        "watermelon"
    ]

# User selected option
def alphabet_substitution(text, noReplacements):
    # Map the character to its special character look alike
    charMap = {
        'a': '@', 'b': '8', 'c': '(', 'i': '!', 'k': '<', 'l': '1', 'o': '0', 's': '$', 't': '7', 'z': '2'
    }

    # Find characters index that can be replaced
    replaceableIndixes = [i for i, char in enumerate(text) if char in charMap]
    
    # Select random index
    replaceRandomIndixe = secrets.SystemRandom().sample(replaceableIndixes, min(noReplacements, len(replaceableIndixes)))
    
    # Replace random index to special characters
    for i in replaceRandomIndixe:
        text[i] = charMap[text[i]]

    return text

def random_capitalisation(text):
    # Capitalize characters randomly
    for i in range(len(text)):
        if secrets.randbelow(2): # 50% to cap
            text[i] = text[i].upper()
    return text

# noWords = Number of words to be included in the password
# noReplacements = How many characters to be replaced by its special character equivalant
def passphrase_generator(noWords=4, noReplacements=3):
    # Define the Alphabets, Numbers and Special Character for random word generation using secrets
    alphabet = string.ascii_letters + string.digits

    wordList = get_word_list()

    while True:
        # Random list of words is generated
        words = [secrets.choice(wordList) for _ in range(noWords)]

        # Combine the words, number, and special character
        password = ''.join(words)
        
        # Convert password to list for easier manipulation
        passwordList = list(password.lower())

        # Add random capitalization and randomly replace characters with its special character
        finalPassList = random_capitalisation(alphabet_substitution(passwordList, noReplacements))

        # Append 2 different random numbers in front and at the end of the password
        finalPass = ''.join(secrets.choice(alphabet) for _ in range(4)) + ''.join(finalPassList) + ''.join(secrets.choice(alphabet) for _ in range(4))

        return finalPass

# Default Option
def password_generator(upperCase=2, noDigit=3):
    # Get all characters, special characters and digits
    alphabet = string.ascii_letters + string.digits
    loop = True

    # Create strong password
    while loop:
        password = ''.join(secrets.choice(alphabet) for _ in range(12))

        # Check if the password has the required user defined parameter
        if (any(c.islower() for c in password)
                and sum(c.isupper() for c in password) >= upperCase
                and sum(c.isdigit() for c in password) >= noDigit):
            
            return password
