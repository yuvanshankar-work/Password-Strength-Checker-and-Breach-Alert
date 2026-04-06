import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import re
import random
import string
import logging
import json
import argparse
import sys
from functools import lru_cache

from zxcvbn import zxcvbn

logging.basicConfig(filename='password_checker.log', level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

class Wordlist:
    """Class to handle wordlists for password checking."""

    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    def load_wordlist(self):
        """Load wordlist from file."""
        if self.file_path in self._cache:
            return self._cache[self.file_path]

        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                wordlist = [line.strip() for line in file]
                self._cache[self.file_path] = wordlist
                return wordlist
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Error: File '{self.file_path}' not found.") from e
        except Exception as e:
            raise RuntimeError(
                f"Error loading wordlist from '{self.file_path}': {str(e)}"
            ) from e

    def is_word_in_list(self, word):
        """Check if a word is in the wordlist."""
        return word in self.words

# pylint: disable=R0903
class StrengthResult:
    """Class to store password strength check results."""

    def __init__(self, strength: str, score: int, message: str):
        self.strength = strength
        self.score = score
        self.message = message

class PasswordStrength:
    """Class to handle password strength checking and related operations."""

    def __init__(self, weak_wordlist_path: str = "./weak_passwords.txt",
        banned_wordlist_path: str = "./banned_passwords.txt"):
        self.weak_wordlist = (Wordlist(weak_wordlist_path)
            if weak_wordlist_path else None)
        self.banned_wordlist = (Wordlist(banned_wordlist_path)
            if banned_wordlist_path else None)
        self.min_password_length = 12
        self.strength_mapping = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

    @lru_cache(maxsize=1000)
    def check_password_strength(self, password: str) -> StrengthResult:
        """Check the strength of a given password."""
        if len(password) < self.min_password_length:
            return StrengthResult("Too short", 0, "Password should be at least 12 characters long.")

        if self.weak_wordlist and self.weak_wordlist.is_word_in_list(password):
            return StrengthResult("Weak", 0, "Password is commonly used and easily guessable.")

        if self.banned_wordlist and self.banned_wordlist.is_word_in_list(password):
            return StrengthResult("Banned", 0,
                "This password is not allowed, as it is commonly found in data leaks.")

        password_strength = zxcvbn(password)
        score = password_strength["score"]
        strength = self.strength_mapping[score]
        complexity_issues = []
        if not re.search(r'[A-Z]', password):
            complexity_issues.append("uppercase letter")
        if not re.search(r'[a-z]', password):
            complexity_issues.append("lowercase letter")
        if not re.search(r'\d', password):
            complexity_issues.append("number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            complexity_issues.append("special character")

        if complexity_issues:
            return StrengthResult("Weak", score,
                f"Password lacks complexity. Missing: {', '.join(complexity_issues)}.")

        if score >= 3:
            return StrengthResult(strength, score,
                f"Password meets all the requirements. Score: {score}/4")

        suggestions = password_strength["feedback"]["suggestions"]
        return StrengthResult(strength, score,
            f"Password is {strength.lower()}. Suggestions: {', '.join(suggestions)}")

    def generate_random_password(self, length=16):
        """Generate a random password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def suggest_improvements(self, password: str) -> str:
        """Suggest improvements for a given password."""
        result = self.check_password_strength(password)
        suggestions = []

        if len(password) < self.min_password_length:
            suggestions.append(f"Increase length to at least {self.min_password_length} characters")

        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        if not re.search(r'\d', password):
            suggestions.append("Add numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            suggestions.append("Add special characters")

        if not suggestions:
            suggestions = result.message.split("Suggestions: ")[-1].split(", ")

        return "Suggested improvements:\n\n" + "\n".join(f"- {s}" for s in suggestions)

# pylint: disable=R0902
class PasswordStrengthGUI:
    """GUI class for Password Strength Checker."""

    def __init__(self, master):
        self.master = master
        master.title("Password Strength Checker")
        master.geometry("760x640")
        master.resizable(False, False)
        master.configure(bg='#eef5fb', padx=18, pady=18)

        self.password_strength = PasswordStrength()
        self.current_progress = 0
        self.animation_id = None

        style = ttk.Style(master)
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'), foreground='#ffffff', background='#1f4f7a')
        style.configure('Subtitle.TLabel', font=('Segoe UI', 10), foreground='#dae9f5', background='#1f4f7a')
        style.configure('Section.TLabel', font=('Segoe UI', 11, 'bold'), foreground='#23334b', background='#eef5fb')
        style.configure('Info.TLabel', font=('Segoe UI', 10), foreground='#3d5168', background='#eef5fb', wraplength=660)
        style.configure('Tip.TLabel', font=('Segoe UI', 9), foreground='#4a5a71', background='#f6fbff', wraplength=660)
        style.configure('Card.TFrame', background='#ffffff')
        style.configure('Card.TLabelframe', background='#ffffff', borderwidth=0)
        style.configure('Card.TLabelframe.Label', font=('Segoe UI', 12, 'bold'), foreground='#1f4b7b', background='#ffffff')
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=8)
        style.configure('TEntry', fieldbackground='#ffffff', background='#ffffff', padding=6)
        style.configure('TCheckbutton', background='#eef5fb', font=('Segoe UI', 10))
        style.map('TButton', background=[('active', '#4a90e2'), ('pressed', '#377cc4'), ('!disabled', '#4a8ad6')], foreground=[('active', '#ffffff'), ('!disabled', '#ffffff')])

        header_frame = tk.Frame(master, bg='#1f4f7a', height=90)
        header_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 14))
        header_frame.grid_propagate(False)

        self.header_label = ttk.Label(header_frame, text="Password Strength Checker", style='Title.TLabel')
        self.header_label.grid(row=0, column=0, sticky='w', padx=18, pady=(18, 0))

        self.subtitle_label = ttk.Label(header_frame, text="Real-time password scoring, suggestions, and generation in a clean dashboard.", style='Subtitle.TLabel')
        self.subtitle_label.grid(row=1, column=0, sticky='w', padx=18, pady=(4, 12))

        self.input_frame = ttk.Frame(master, style='Card.TFrame', padding=(16, 16))
        self.input_frame.grid(row=1, column=0, columnspan=2, sticky='ew')
        self.input_frame.columnconfigure(0, weight=1)

        self.password_label = ttk.Label(self.input_frame, text="Enter password", style='Section.TLabel')
        self.password_label.grid(row=0, column=0, sticky='w')

        self.password_entry = ttk.Entry(self.input_frame, show="*", font=('Segoe UI', 11), width=60)
        self.password_entry.grid(row=1, column=0, sticky='ew', pady=(8, 10))
        self.password_entry.bind('<Return>', lambda event: self.check_password())

        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_check = ttk.Checkbutton(
            self.input_frame,
            text="Show password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            style='TCheckbutton'
        )
        self.show_password_check.grid(row=1, column=1, padx=(12, 0), sticky='w')

        self.button_frame = ttk.Frame(master, style='Card.TFrame')
        self.button_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(2, 14))
        self.button_frame.columnconfigure((0, 1, 2), weight=1)

        self.check_button = ttk.Button(self.button_frame, text="Check Strength", command=self.check_password)
        self.check_button.grid(row=0, column=0, padx=6, pady=4, sticky='ew')
        self.generate_button = ttk.Button(self.button_frame, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=0, column=1, padx=6, pady=4, sticky='ew')
        self.export_button = ttk.Button(self.button_frame, text="Export Results", command=self.export_results)
        self.export_button.grid(row=0, column=2, padx=6, pady=4, sticky='ew')

        self.result_frame = ttk.LabelFrame(master, text="Strength Analysis", style='Card.TLabelframe', padding=(18, 16))
        self.result_frame.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(0, 14))
        self.result_frame.columnconfigure(0, weight=1)

        self.strength_label = ttk.Label(self.result_frame, text="Current status", style='Section.TLabel')
        self.strength_label.grid(row=0, column=0, sticky='w')

        self.status_label = ttk.Label(self.result_frame, text="Ready to analyze a password.", style='Info.TLabel', justify='left')
        self.status_label.grid(row=1, column=0, sticky='w', pady=(10, 10))

        self.gauge_canvas = tk.Canvas(self.result_frame, width=700, height=70, bg='#ffffff', highlightthickness=0)
        self.gauge_canvas.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        self.gauge_canvas.create_rectangle(10, 30, 690, 42, fill='#d9e8f5', outline='')
        self.gauge_fill = self.gauge_canvas.create_rectangle(10, 30, 10, 42, fill='#5cb85c', outline='')
        self.gauge_text = self.gauge_canvas.create_text(350, 18, text='0%', font=('Segoe UI', 11, 'bold'), fill='#1f4b7a')

        self.message_label = ttk.Label(self.result_frame, text="Feedback will appear here once a password is analyzed.", style='Info.TLabel', justify='left')
        self.message_label.grid(row=3, column=0, sticky='w', pady=(0, 12))

        self.feedback_text = tk.Text(self.result_frame, height=5, bg='#f6fbff', bd=0, highlightthickness=1, highlightbackground='#d3e6f5', wrap='word', font=('Segoe UI', 10))
        self.feedback_text.grid(row=4, column=0, sticky='ew')
        self.feedback_text.configure(state='disabled')

        self.generator_frame = ttk.LabelFrame(master, text="Generated Password", style='Card.TLabelframe', padding=(16, 14))
        self.generator_frame.grid(row=4, column=0, columnspan=2, sticky='ew', pady=(0, 14))
        self.generator_frame.columnconfigure(0, weight=1)

        self.password_display = ttk.Entry(self.generator_frame, font=('Segoe UI', 11), width=60)
        self.password_display.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        self.password_display.state(['readonly'])

        self.copy_button = ttk.Button(self.generator_frame, text="Copy to Clipboard", command=self.copy_password)
        self.copy_button.grid(row=1, column=0, sticky='ew')

        self.tip_frame = ttk.LabelFrame(master, text="Security Tips", style='Card.TLabelframe', padding=(16, 14))
        self.tip_frame.grid(row=5, column=0, columnspan=2, sticky='ew')

        self.tip_label = ttk.Label(self.tip_frame,
            text="• Use a unique password for every account\n"
                 "• Include uppercase, lowercase, digits, and symbols\n"
                 "• Avoid personal information and common words\n"
                 "• Make passwords longer than 12 characters\n"
                 "• Use a password manager to store passwords securely",
            style='Tip.TLabel', justify='left')
        self.tip_label.grid(row=0, column=0, sticky='w')

        self.results = []

    def check_password(self):
        """Check the strength of the entered password."""
        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password to check.")
            return

        result = self.password_strength.check_password_strength(password)
        self.status_label.config(text=f"{result.strength}")
        self.message_label.config(text=result.message)
        self.message_label.configure(foreground=self.get_strength_color(result.score))

        self.update_feedback_text(self.password_strength.suggest_improvements(password))
        self.animate_strength_bar((result.score / 4) * 100, result.score)

        self.results.append({
            "password": password,
            "strength": result.strength,
            "message": result.message
        })
        logging.info("Password checked: %s", result.strength)

    def update_feedback_text(self, text):
        self.feedback_text.configure(state='normal')
        self.feedback_text.delete('1.0', tk.END)
        self.feedback_text.insert(tk.END, text)
        self.feedback_text.configure(state='disabled')

    def animate_strength_bar(self, target_value, score):
        if self.animation_id:
            self.master.after_cancel(self.animation_id)

        if self.current_progress < target_value:
            self.current_progress = min(self.current_progress + 4, target_value)
        elif self.current_progress > target_value:
            self.current_progress = max(self.current_progress - 4, target_value)

        fill_end = 10 + int((680 * self.current_progress) / 100)
        self.gauge_canvas.coords(self.gauge_fill, 10, 30, fill_end, 42)
        self.gauge_canvas.itemconfig(self.gauge_text, text=f"{int(self.current_progress)}%")
        self.gauge_canvas.itemconfig(self.gauge_fill, fill=self.get_strength_color(score))

        if self.current_progress != target_value:
            self.animation_id = self.master.after(12, lambda: self.animate_strength_bar(target_value, score))

    def get_strength_color(self, score):
        if score <= 1:
            return '#d64550'
        if score == 2:
            return '#f39c12'
        if score == 3:
            return '#5fba7d'
        return '#3271da'

    def toggle_password_visibility(self):
        """Toggle the visibility of the password entry."""
        self.password_entry.config(show='' if self.show_password_var.get() else '*')

    def generate_password(self):
        """Generate a random strong password."""
        password = self.password_strength.generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

        self.password_display.state(['!readonly'])
        self.password_display.delete(0, tk.END)
        self.password_display.insert(0, password)
        self.password_display.state(['readonly'])

        copy_to_clipboard = messagebox.askyesno(
            "Generated Password",
            f"Generated password: {password}\n\nDo you want to copy the password to clipboard?"
        )
        if copy_to_clipboard:
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            messagebox.showinfo("Clipboard", "Password copied to clipboard.")

    def copy_password(self):
        """Copy the password from the display field to clipboard."""
        password = self.password_display.get().strip()
        if not password:
            messagebox.showwarning("Clipboard", "No generated password to copy.")
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        messagebox.showinfo("Clipboard", "Password copied to clipboard.")

    def export_results(self):
        """Export the password check results to a JSON file."""
        if not self.results:
            messagebox.showerror("Error", "No results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not file_path:
            return
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(self.results, file, indent=4)
        messagebox.showinfo("Export Successful", f"Results exported to {file_path}.")

class PasswordStrengthCLI:
    """CLI interface for Password Strength Checker."""

    def __init__(self):
        self.password_strength = PasswordStrength()

    def check_password(self, password):
        """Check password strength and print results."""
        result = self.password_strength.check_password_strength(password)
        print(f"\nStrength: {result.strength}")
        print(f"Message: {result.message}")
        print(self.password_strength.suggest_improvements(password))

    def generate_password(self, length=16):
        """Generate and display a random password."""
        password = self.password_strength.generate_random_password(length)
        print(f"\nGenerated Password: {password}")
        self.check_password(password)
        return password

def main():
    """Main entry point for both GUI and CLI interfaces."""
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--check", type=str, help="Check strength of provided password")
    parser.add_argument("--generate", action="store_true", help="Generate a strong password")
    parser.add_argument("--length", type=int, default=16, help="Length of generated password")

    args = parser.parse_args()

    if args.cli or args.check or args.generate:
        cli = PasswordStrengthCLI()
        if args.check:
            cli.check_password(args.check)
        elif args.generate:
            cli.generate_password(args.length)
        elif args.cli:
            while True:
                print("\nPassword Strength Checker CLI")
                print("1. Check Password Strength")
                print("2. Generate Strong Password")
                print("3. Exit")
                choice = input("\nEnter your choice (1-3): ")

                if choice == "1":
                    password = input("Enter password to check: ")
                    cli.check_password(password)
                elif choice == "2":
                    length = input("Enter desired password length (default 16): ")
                    try:
                        length = int(length) if length else 16
                        cli.generate_password(length)
                    except ValueError:
                        print("Invalid length. Using default length of 16.")
                        cli.generate_password()
                elif choice == "3":
                    print("Goodbye!")
                    sys.exit(0)
                else:
                    print("Invalid choice. Please try again.")
    else:
        root = tk.Tk()
        PasswordStrengthGUI(root)
        root.mainloop()

if __name__ == "__main__":
    main()
