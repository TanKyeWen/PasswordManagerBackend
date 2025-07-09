import string
import secrets
import re
import zxcvbn

def get_word_list():
    # Load a word list from a file or define it directly
    # For simplicity, we can use a small sample list here
    return [
        "raid", "tooth", "hour", "pair", "offspring", "dimension", "evolution",
        "fail", "superior", "provide", "researcher", "spirit", "inquiry", "horn",
        "drawing", "yard", "wolf", "prove", "recruit", "breed", "enlarge",
        "conception", "tumble", "incident", "acid", "sail", "sacrifice", "treaty", "cattle",
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

def get_char_set(capAlphabet=True, lowerAlphabet=True, specialChar=True):
    # Define the character set based on user preferences
    charSet = ''
    if capAlphabet:
        charSet += string.ascii_uppercase
    if lowerAlphabet:
        charSet += string.ascii_lowercase
    if specialChar:
        charSet += string.punctuation
    return charSet

# noWords = Number of words to be included in the password
def passphrase_generator(noWords=4, capAlphabet=True, lowerAlphabet=True, specialChar=True):
    # Define the Alphabets, Numbers and Special Character for random word generation using secrets
    alphabet = get_char_set(capAlphabet, lowerAlphabet, specialChar)

    wordList = get_word_list()

    while True:
        # Random list of words is generated
        words = [secrets.choice(wordList) for _ in range(noWords)]

        # Combine the words, number, and special character
        password = ''.join(words)
        
        # Convert password to list for easier manipulation
        passwordList = list(password.lower())

        # Add random capitalization and randomly replace characters with its special character
        finalPassList = random_capitalisation(alphabet_substitution(passwordList, 4))

        # Append 2 different random numbers in front and at the end of the password
        finalPass = ''.join(secrets.choice(alphabet) for _ in range(4)) + ''.join(finalPassList) + ''.join(secrets.choice(alphabet) for _ in range(4))

        return finalPass

# Default Option
def password_generator(maxLength=16, minLength=8, capAlphabet=True, lowerAlphabet=True, specialChar=True):
    # Get all characters, special characters and digits
    alphabet = get_char_set(capAlphabet, lowerAlphabet, specialChar)
    
    # Create strong password
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(12))
        passwordList = list(password)
        finalPass = random_capitalisation(alphabet_substitution(passwordList, 4))

        # Check if the password has the required user defined parameter
        if (any(c.islower() for c in finalPass)
                and sum(c.isdigit() for c in finalPass) >= minLength
                and sum(c.isdigit() for c in finalPass) <= maxLength):
            
            return password