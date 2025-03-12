import getpass
import re
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    if len(password) < 8:
        print("Hasło musi mieć co najmniej 8 znaków.")
        return False
    if not re.search("[a-zA-Z]", password):
        print("Hasło musi zawierać co najmniej jedną literę.")
        return False
    if not re.search("[0-9]", password):
        print("Hasło musi zawierać co najmniej jedną cyfrę.")
        return False
    if not re.search("[A-Z]", password):
        print("Hasło musi zawierać co najmniej jedną dużą literę.")
        return False
    if not re.search(r" [ !@#$%^&*(),.?\":{}|<>]", password):
        print("Hasło musi zawierać co najmniej jeden znak specjalny.")
        return False
    return True

def register():
    print("Rejestracja:")
    username = input("Podaj login: ")
    
    while True:
        password = getpass.getpass("Podaj hasło: ")
        if validate_password(password):
            break
    
    hashed_password = hash_password(password)
    
    with open("credentials.txt", "w") as file:
        file.write(f"{username}\n")
        file.write(f"{hashed_password}\n")
    
    print("Dane zostały zapisane.")
    return username, hashed_password

def login():
    print("Logowanie:")
    username = input("Podaj login: ")
    password = getpass.getpass("Podaj hasło: ")
    
    hashed_password = hash_password(password)
    
    try:
        with open("credentials.txt", "r") as file:
            stored_username = file.readline().strip()
            stored_password = file.readline().strip()
    except FileNotFoundError:
        print("Brak zapisanych danych. Zarejestruj się najpierw.")
        return
    
    if username == stored_username and hashed_password == stored_password:
        print("Dane podane poprawnie")
    else:
        print("Błędny login lub hasło")

def main():
    while True:
        choice = input("Wybierz opcję: [1] Rejestracja, [2] Logowanie, [3] Wyjście: ")
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            break
        else:
            print("Nieprawidłowy wybór. Spróbuj ponownie.")

if __name__ == "__main__": 
    main()
