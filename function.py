import random
from string import ascii_uppercase, ascii_lowercase
from cryptography.fernet import Fernet

def generate_key():
	""" Generates a fernet key for encryption. """
	key = Fernet.generate_key()
	return key

def encrypt_pass(pw, user, key):
	"""Encrypts the password."""

	concat = pw + user
	new_pw = [chr((ord(ch)) + 2) for i,ch in enumerate(concat)]
	temp = []
		
	for i, ch in enumerate(new_pw):
		if i % 2 == 0:
			temp.insert(0,ch)
		else:
			temp.append(ch)
		
	temp.append(new_pw[0])
	temp.insert(0, new_pw[-1])
		
	final_pass = "".join(temp)
	fernet = Fernet(key)
	return fernet.encrypt(final_pass.encode())
		
def decrypt_pass(pw, user, key):
	"""Decrypts the password passed."""

	fernet = Fernet(key)
	decoded_pass = fernet.decrypt(pw).decode()

	new_pw = [chr((ord(ch)) - 2) for i,ch in enumerate(decoded_pass)]
	temp = []
	new_pw.pop()
	new_pw.remove(new_pw[0])
		
	back = len(new_pw) -1
	front = 0
	flag = True if len(new_pw) % 2 == 1 else False
		
	for _ in range(len(new_pw)):
		if flag:
			temp.insert(0,new_pw[front])
			front += 1
		else:
			temp.insert(0,new_pw[back])
			back -= 1

		flag = not flag

	return "".join(temp[0:-(len(user))])

def check_empty(ui, ss, *args):
	"""Checks if the entry field for text edit(s) is/are empty."""
	for arg in args:
		if not arg:
			show_message(ui,"Please input text fields.", ss)
			return True
	return False

def show_message(ui, text, ss):
	"""Shows a feedback in label form."""
	ui.label_error.setStyleSheet(ss)
	ui.label_error.setText(text)
	ui.label_error.show()


def generate_pass():
	"""Generates a random password."""
	# List of characters for the password generator
	letters = list(ascii_lowercase) + list(ascii_uppercase)
	num = list('1234567890')
	symbols = list('!@$)(^&')

	# Create a random number of characters for each:
	letter_len = random.randint(8,10)
	number_len = random.randint(3,5)
	symbol_len = random.randint(1,2)

	# Concatenate
	r_letters = [random.choice(letters) for _ in range(letter_len)]
	r_numbers = [random.choice(num) for _ in range(number_len)]
	r_symbols = [random.choice(symbols) for _ in range(symbol_len)]
	password_list = r_letters + r_numbers + r_symbols

	# Shuffle
	random.shuffle(password_list)

	return "".join(password_list)



	



