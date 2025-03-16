import getpass
import re
import hashlib
import random
import smtplib
from email.mime.text import MIMEText
import requests

# Konfiguracja Textbelt
TEXTBELT_API_KEY = 'your_textbelt_api_key'
CREDENTIALS_FILE = "Auten.txt"

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
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Hasło musi zawierać co najmniej jeden znak specjalny.")
        return False
    return True

def load_credentials():
    credentials = {}
    try:
        with open(CREDENTIALS_FILE, "r") as file:
            for line in file:
                line = line.strip()
                parts = line.split(':')
                if len(parts) == 4:
                    username, hashed_password, phone, email = parts
                    credentials[username] = (hashed_password, phone, email)
    except FileNotFoundError:
        pass
    print(f"Załadowane dane uwierzytelniające: {credentials}")  # Debugowanie
    return credentials

def save_credentials(credentials):
    try:
        with open(CREDENTIALS_FILE, "w") as file:
            for username, (hashed_password, phone, email) in credentials.items():
                file.write(f"{username}:{hashed_password}:{phone}:{email}\n")
        print("Dane zostały zapisane pomyślnie.")
    except Exception as e:
        print(f"Błąd podczas zapisywania danych: {e}")

def generate_code():
    return str(random.randint(1000, 9999))

def send_email(email, code):
    msg = MIMEText(f"Twój kod weryfikacyjny to: {code}")
    msg['Subject'] = 'Kod weryfikacyjny'
    msg['From'] = 'your_email@gmail.com'
    msg['To'] = email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login('your_email@gmail.com', 'your_email_password')  # Upewnij się, że używasz poprawnych danych logowania
            server.sendmail('your_email@gmail.com', [email], msg.as_string())
        print(f"E-mail wysłany na {email}: Kod weryfikacyjny to {code}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"Błąd podczas wysyłania e-maila: {e}")
        print("Sprawdź nazwę użytkownika i hasło oraz upewnij się, że dostęp dla mniej bezpiecznych aplikacji jest włączony.")
        print("Jeśli masz włączone uwierzytelnianie dwuskładnikowe, użyj hasła aplikacji.")
    except Exception as e:
        print(f"Błąd podczas wysyłania e-maila: {e}")

def send_sms(phone, code):
    url = 'https://textbelt.com/text'
    data = {
        'phone': phone,
        'message': f"Twój kod weryfikacyjny to: {code}",
        'key': TEXTBELT_API_KEY
    }
    response = requests.post(url, data=data)
    result = response.json()
    print(f"Response from Textbelt: {result}")  # Debugowanie
    if result['success']:
        print(f"SMS wysłany na {phone}: Kod weryfikacyjny to {code}")
        return True
    else:
        print(f"Błąd podczas wysyłania SMS-a: {result['error']}")
        return False

def register():
    print("Rejestracja:")
    credentials = load_credentials()
    username = input("Podaj login: ")
    
    if username in credentials:
        print("Login już istnieje. Masz 3 próby na wprowadzenie poprawnego hasła.")
        attempts = 3
        while attempts > 0:
            password = getpass.getpass("Podaj hasło: ")
            if validate_password(password):
                hashed_password = hash_password(password)
                if hashed_password in [cred[0] for cred in credentials.values()]:
                    print("To hasło jest już używane. Wprowadź inne hasło.")
                    continue
                phone = input("Podaj numer telefonu: ")
                email = input("Podaj adres e-mail: ")
                credentials[username] = (hashed_password, phone, email)
                save_credentials(credentials)
                print("Dane zostały zapisane.")
                return username, hashed_password
            else:
                attempts -= 1
                print(f"Niepoprawne hasło. Pozostało prób: {attempts}")
        print("Przekroczono limit prób. Program zakończony.")
        return
    else:
        while True:
            password = getpass.getpass("Podaj hasło: ")
            if validate_password(password):
                hashed_password = hash_password(password)
                if hashed_password in [cred[0] for cred in credentials.values()]:
                    print("To hasło jest już używane. Wprowadź inne hasło.")
                    continue
                break
        
        phone = input("Podaj numer telefonu: ")
        email = input("Podaj adres e-mail: ")
        
        credentials[username] = (hashed_password, phone, email)
        print(f"Zapisywanie danych: {credentials}")  # Wiadomość debugowania
        save_credentials(credentials)
        
        print("Dane zostały zapisane.")
        return username, hashed_password

def login():
    print("Logowanie:")
    credentials = load_credentials()
    username = input("Podaj login: ")
    password = getpass.getpass("Podaj hasło: ")
    
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")  # Debugowanie
    
    if username not in credentials:
        print("Błędny login")
    elif credentials[username][0] != hashed_password:
        print("Błędne hasło")
        print(f"Oczekiwane hasło: {credentials[username][0]}")  # Debugowanie
    else:
        phone = credentials[username][1]
        email = credentials[username][2]
        
        # Weryfikacja numeru telefonu
        phone_code = generate_code()
        if send_sms(phone, phone_code):
            user_phone_code = input("Podaj kod weryfikacyjny z telefonu: ")
            if user_phone_code != phone_code:
                print("Błędny kod weryfikacyjny z telefonu.")
                return
        else:
            print("Przechodzenie do weryfikacji e-maila z powodu problemu z SMS.")
        
        # Weryfikacja adresu e-mail
        email_code = generate_code()
        send_email(email, email_code)
        user_email_code = input("Podaj kod weryfikacyjny z e-maila: ")
        if user_email_code != email_code:
            print("Błędny kod weryfikacyjny z e-maila.")
            return
        
        print("Logowanie zakończone sukcesem")
        print(f"Numer telefonu: {phone}")
        print(f"Adres e-mail: {email}")

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
