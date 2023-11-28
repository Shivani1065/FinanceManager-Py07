import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkcalendar import DateEntry
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import hashlib

# SQLite Database Initialization
conn = sqlite3.connect('expenses.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        category TEXT,
        amount REAL,
        date TEXT
    )
''')
conn.commit()


class PersonalFinanceManager:
    def __init__(self, root):
        # Initialize the main application window
        self.root = root
        self.root.title("Personal Finance Manager")
        # Setting up the GUI style
        self.setup_style()
        # Create the main frame
        self.create_main_frame()

        # Initialize variables for budget and user ID
        self.date_cal = None
        self.report_window = None
        self.budget_window = None
        self.budget = 0
        self.user_id = None


    def setup_style(self):
        """
        Set up the visual style for the application using ttk.Style.
        This method configures the visual style of various elements in the application
        using the ttk.Style class. It defines colors for background, button background,
        and button foreground. The styles for frames, buttons, labels, entries, and
        Treeview elements are configured accordingly.
        Returns:
        None
        """
        
         # Configure the visual style using ttk.Style
        style = ttk.Style()
        style.theme_use("classic")

        # Define colors
        bg_color = "#F0F0F0"
        button_bg_color = "#4CAF50"
        button_fg_color = "white"

        # Configure style for different elements
        style.configure("TFrame", background=bg_color)
        style.configure("TButton", padding=10, font=("Helvetica", 12),
                        background=button_bg_color, foreground=button_fg_color)
        style.map("TButton", background=[("active", "#45a049")])
        style.configure("TLabel", font=("Helvetica", 12), background=bg_color)
        style.configure("TEntry", font=("Helvetica", 12), relief="flat")
        style.map("TEntry", relief=[('active', 'flat')])
        style.configure("Treeview.Heading", font=("Helvetica", 12),
                        background=button_bg_color, foreground=button_fg_color)
        style.configure("Treeview", font=(
            "Helvetica", 11), background=bg_color)
        

    def create_main_frame(self):
        """
        Create the main frame of the application.
        This method creates the main frame using ttk.Frame, sets its padding and style,
        and places it in the grid layout. It also calls the method to add buttons to the main frame.
        Returns:
        None
        """
        self.main_frame = ttk.Frame(self.root, padding="10", style="TFrame")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
         # Add buttons to the main frame
        self.add_buttons_to_main_frame()


    def add_buttons_to_main_frame(self):
        """
        Add buttons for different functionalities to the main frame.
        This method creates and configures various buttons for different functionalities,
        such as setting a budget, viewing a budget, adding expenses, generating a financial report,
        exiting the application, logging in, registering, and deleting an account.
        Returns:
        None
        """
        # Button for setting for Budget
        self.set_budget_button = ttk.Button(
            self.main_frame, text="Set Budget", command=self.set_budget, state=tk.DISABLED)
        self.set_budget_button.grid(row=0, column=0, padx=5, pady=5)
       
        # ... (similar configurations for other buttons)
        # Button for viewing a budget
        self.view_budget_button = ttk.Button(
            self.main_frame, text="View Budget", command=self.view_budget, state=tk.DISABLED)
        self.view_budget_button.grid(row=0, column=1, padx=5, pady=5)

        # Button for adding expenses
        self.add_expense_button = ttk.Button(
            self.main_frame, text="Add Expenses", command=self.show_add_expense, state=tk.DISABLED)
        self.add_expense_button.grid(row=0, column=2, padx=5, pady=5)

         # Button for generating a financial report
        self.generate_report_button = ttk.Button(
            self.main_frame, text="Generate Financial Report", command=self.generate_report, state=tk.DISABLED)
        self.generate_report_button.grid(row=0, column=3, padx=5, pady=5)

        # Button for exiting the application
        self.exit_button = ttk.Button(
            self.main_frame, text="Exit", command=self.root.destroy)
        self.exit_button.grid(row=0, column=4, padx=5, pady=5)

        # Button for logging in
        self.login_button = ttk.Button(
            self.main_frame, text="Login", command=self.show_login_window)
        self.login_button.grid(row=0, column=5, padx=5, pady=5)

        # Button for registering
        self.register_button = ttk.Button(
            self.main_frame, text="Register", command=self.show_register_window)
        self.register_button.grid(row=0, column=6, padx=5, pady=5)

        # Button for deleting an account
        self.delete_account_button = ttk.Button(
            self.main_frame, text="Delete Account", command=self.show_delete_account_window, state=tk.DISABLED)
        self.delete_account_button.grid(row=0, column=8, padx=5, pady=5)
    
    #reset for the password 
    def show_reset_password_window(self):
        # Placeholder function - intended to show a window for resetting the password.
        pass
    
    #submit the reset password
    def submit_reset_password(self, old_password, new_password):
        # Placeholder function - intended to submit the request to reset the password.
        pass

    def show_delete_account_window(self):
        """ Display a confirmation window for deleting the user's account.
        This function prompts the user with a confirmation window to confirm the deletion
        of their account. If the user confirms, the account is deleted from the database,
        and a success message is shown. The user is then logged out.
        Returns:
        None
        """
        # Display a confirmation window for deleting the user's account.
        confirmation = messagebox.askyesno(
            "Confirmation", "Are you sure you want to delete your account?")
        if confirmation:
            # If user confirms, delete the account from the database.
            cursor.execute("DELETE FROM users WHERE id=?", (self.user_id,))
            conn.commit()
            messagebox.showinfo(
                "Account Deleted", "Your account has been successfully deleted.")
             # Logout the user after deleting the account.
            self.logout()

    def logout(self):
        """ Log out the user and disable relevant buttons.
        This function logs out the user by setting the user_id to None and disabling
        relevant buttons in the user interface. After logging out, the user loses
        access to certain functionalities until they log in again.
        Returns:
        None
        """
        # Log out the user and disable relevant buttons.
        self.user_id = None
        # Disable buttons after logout
        self.add_expense_button["state"] = tk.DISABLED
        self.generate_report_button["state"] = tk.DISABLED
        self.set_budget_button["state"] = tk.DISABLED
        self.view_budget_button["state"] = tk.DISABLED
        self.delete_account_button["state"] = tk.DISABLED

    def show_login_window(self):
        """
        Display the login window for users to enter credentials.
        This method creates a new Toplevel window for the login interface. It includes
        entry fields for the username and password, along with a button to submit the login credentials.
        Returns:
        None
    """
        # Display the login window for users to enter credentials.
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login")

        # Label and entry field for the username
        self.username_label = ttk.Label(
            self.login_window, text="Username:", style="TLabel")
        self.username_label.grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(
            self.login_window, justify="right", style="TEntry")
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        # Label and entry field for the password (masked with '*')
        self.password_label = ttk.Label(
            self.login_window, text="Password:", style="TLabel")
        self.password_label.grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(
            self.login_window, justify="right", show="*", style="TEntry")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Button to submit the login credentials
        self.submit_login_button = ttk.Button(
            self.login_window, text="Login", command=self.validate_login)
        self.submit_login_button.grid(row=2, column=0, columnspan=2, pady=10)

    def validate_login(self):
        """
        Validate user login credentials.
        This function retrieves the entered username and password, queries the database
        to verify the credentials, and takes appropriate actions based on the result.
        If the login is successful, it sets the user ID, displays a welcome message,
        and enables specific buttons in the user interface. If the login fails, it shows an error message.
        Returns:
        None
        """
        # Validate user login credentials.
        username = self.username_entry.get().lower()
        password = self.password_entry.get()

        # Query the database to retrieve user information.
        cursor.execute(
            "SELECT id, password FROM users WHERE username=?", (username,))
        user_record = cursor.fetchone()

        # Check if the user exists and the password is correct.
        if user_record and self.verify_password(password, user_record[1]):
            # If login is successful, set user ID and show a welcome message.
            self.user_id = user_record[0]
            messagebox.showinfo("Login Successful",
                                f"Welcome, {username.capitalize()}!")
            self.login_window.destroy()

            # Enable buttons after successful login
            self.add_expense_button["state"] = tk.NORMAL
            self.generate_report_button["state"] = tk.NORMAL
            self.set_budget_button["state"] = tk.NORMAL
            # Enable Delete Account button
            self.delete_account_button["state"] = tk.NORMAL
        else:
            # If login fails, show an error message.
            messagebox.showerror(
                "Login Failed", "Invalid credentials. Try again.")

    
    def show_register_window(self):
        """
        Display the registration window.
        This function creates a new Toplevel window for the registration interface.
        It includes label and entry fields for the new username, new password, and
        confirmation of the new password. Additionally, a button is provided to submit
        the registration details.
        Returns:
        None
        """
        # Create a new Toplevel window for the registration interface
        self.register_window = tk.Toplevel(self.root)
        self.register_window.title("Register")

         # Label and entry field for the new username
        self.new_username_label = ttk.Label(
            self.register_window, text="Username:", style="TLabel")
        self.new_username_label.grid(row=0, column=0, padx=5, pady=5)
        self.new_username_entry = ttk.Entry(
            self.register_window, justify="right", style="TEntry")
        self.new_username_entry.grid(row=0, column=1, padx=5, pady=5)

        
        # Label and entry field for the new password (masked with '*')
        self.new_password_label = ttk.Label(
            self.register_window, text="Password:", style="TLabel")
        self.new_password_label.grid(row=1, column=0, padx=5, pady=5)
        self.new_password_entry = ttk.Entry(
            self.register_window, justify="right", show="*", style="TEntry")
        self.new_password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Label and entry field to confirm the new password (masked with '*')
        self.confirm_password_label = ttk.Label(
            self.register_window, text="Confirm Password:", style="TLabel")
        self.confirm_password_label.grid(row=2, column=0, padx=5, pady=5)
        self.confirm_password_entry = ttk.Entry(
            self.register_window, justify="right", show="*", style="TEntry")
        self.confirm_password_entry.grid(row=2, column=1, padx=5, pady=5)

        # Button to submit the registration details
        self.submit_register_button = ttk.Button(
            self.register_window, text="Register", command=self.validate_registration)
        self.submit_register_button.grid(
            row=3, column=0, columnspan=2, pady=10)

    def validate_registration(self):
        """ Validate user registration details.
        This function retrieves the new username, new password, and confirmation
        of the new password from the corresponding entry fields. It checks for
        completeness, matches between passwords, and the existence of the username
        in the database. If all checks pass, the function hashes the password,
        inserts the new user into the database, and displays a success message.
        Finally, it closes the registration window.
        Returns:
        None
        """
        # Retrieve registration details
        new_username = self.new_username_entry.get().lower()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Check for completeness of fields
        if not new_username or not new_password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Check if passwords match
        if new_password != confirm_password:
            messagebox.showerror(
                "Error", "Passwords do not match. Please try again.")
            return

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username=?", (new_username,))
        existing_user = cursor.fetchone()

        if existing_user:
            messagebox.showerror(
                "Error", "Username already exists. Please choose a different username.")
            return

        hashed_password = self.hash_password(new_password)

        # Insert new user into the database
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (new_username, hashed_password))
        conn.commit()
 
        # Display registration success message
        messagebox.showinfo("Registration Successful",
                            "Registration successful!")
        # Close the registration window
        self.register_window.destroy()
     
    def hash_password(self, password):
        # Add a salt to the input password and hash it using SHA-256
        hashed_input_password = hashlib.sha256(
            password.encode() + b'salt_string').hexdigest()
        return hashed_input_password

    def verify_password(self, entered_password, stored_password):
         # Hash the entered password and compare it with the stored password
        hashed_entered_password = hashlib.sha256(
            entered_password.encode() + b'salt_string').hexdigest()
        return hashed_entered_password == stored_password

    def set_budget(self):
        """ Display a window for users to set their budget.
        This method creates a new window where users can input their budget amount.
        """
        # Create the budget window
        self.budget_window = tk.Toplevel(self.root)
        self.budget_window.title("Set Budget")

         # Label for budget input
        self.budget_label = ttk.Label(
            self.budget_window, text="Budget:", style="TLabel")
        self.budget_label.grid(row=0, column=0, padx=5, pady=5)
        # Entry field for budget input
        self.budget_entry = ttk.Entry(
            self.budget_window, justify="right", style="TEntry")
        self.budget_entry.grid(row=0, column=1, padx=5, pady=5)
         # Button to submit the budget
        self.submit_budget_button = ttk.Button(
            self.budget_window, text="Submit", command=self.submit_budget)
        self.submit_budget_button.grid(row=1, column=0, columnspan=2, pady=10)

    def view_budget(self):
        """
        Display the user's current budget.
        This method checks if a budget is set and shows a message with the current budget amount.
        If no budget is set, it notifies the user. Additionally, if a budget is set, it provides
        an option to increase the budget through a button.
        Note: The budget is stored in the 'self.budget' attribute.
        """
        if self.budget == 0:
            # If no budget is set, show a message
            messagebox.showinfo("Budget", "No budget set.")
        else:
            # If a budget is set, show the current budget and add a button to increase it
            messagebox.showinfo(
                "Budget", f"Current Budget: ₹{self.budget:.2f}")
            # Add a button to increase the budget
            increase_button = ttk.Button(
                self.root, text="Increase Budget", command=self.increase_budget)
            increase_button.grid(row=1, column=7, padx=5, pady=5)


    def increase_budget(self):
        """ Display a window to increase the user's budget.
        This method creates a new window with a label and an entry field for the user to input
        the additional budget amount. It also includes a submit button that triggers the
        'submit_increase_budget' method.
        Note: The entered amount is passed to the 'submit_increase_budget' method for processing.
        """
        increase_window = tk.Toplevel(self.root)
        increase_window.title("Increase Budget")
        # Label for entering additional budget amount
        label = ttk.Label(
            increase_window, text="Enter additional budget amount:")
        label.grid(row=0, column=0, padx=5, pady=5)
        # Entry field for the user to input the amount
        entry = ttk.Entry(increase_window)
        entry.grid(row=0, column=1, padx=5, pady=5)
         # Submit button to trigger the 'submit_increase_budget' method
        submit_button = ttk.Button(
            increase_window, text="Submit", command=lambda: self.submit_increase_budget(entry.get(), increase_window))
        submit_button.grid(row=1, column=0, columnspan=2, pady=10)

    def submit_increase_budget(self, additional_amount, increase_window):
        """Process the submission of an increased budget.
        This method validates the entered additional amount, checks if it's a positive number,
        and asks for confirmation before increasing the budget. If confirmed, the budget is
        updated, and a success message is displayed. The increase window is then destroyed.
        Parameters:
        - additional_amount (str): The entered additional budget amount.
        - increase_window (Tkinter.Toplevel): The window for increasing the budget.
         """
        try:
            additional_amount = float(additional_amount)
        except ValueError:
             # If the entered value is not a valid number, show an error message.
            messagebox.showerror("Error", "Amount should be a valid number.")
            return

        if additional_amount <= 0:
            # If the entered value is not a positive number, show an error message.
            messagebox.showerror(
                "Error", "Additional amount should be greater than 0.")
            return

        if messagebox.askyesno("Confirm", f"Increase budget by ₹{additional_amount:.2f}?"):
            # If the user confirms the increase, update the budget and show a success message.
            self.budget += additional_amount
            messagebox.showinfo(
                "Success", f"Budget increased to ₹{self.budget:.2f}")
            increase_window.destroy()

    def submit_budget(self):
        # Get the entered budget as a string and remove leading/trailing whitespaces
        budget_str = self.budget_entry.get().strip()

        try:
            # Convert the budget string to a float.
            new_budget = float(budget_str)
        except ValueError:
            # If the entered value is not a valid number, show an error message.
            messagebox.showerror("Error", "Budget should be a valid number.")
            return

        if messagebox.askyesno("Confirm", f"Set budget to ₹{new_budget:.2f}?"):
            # If the user confirms the new budget, update the budget and show a success message.
            self.budget = new_budget
            messagebox.showinfo(
                "Success", f"Budget set to ₹{self.budget:.2f}")
            self.budget_window.destroy()
              # Enable relevant buttons after setting the budget
            self.add_expense_button["state"] = tk.NORMAL
            self.generate_report_button["state"] = tk.NORMAL
            self.view_budget_button["state"] = tk.NORMAL

    def show_add_expense(self):
        """Display the window for adding expenses.
        This method creates a Toplevel window containing entry fields for expense details,
        such as category, amount, and date. Users can submit expenses through this window.
        Note: This method assumes the existence of certain attributes like add_expense_window,
        category_entry, amount_entry, date_cal, submit_button, back_button, and submit_expense.
        """
        self.add_expense_window = tk.Toplevel(self.root)
        self.add_expense_window.title("Add Expenses")
        # Label and entry field for the expense category
        self.category_label = ttk.Label(
            self.add_expense_window, text="Category:", style="TLabel")
        self.category_label.grid(row=0, column=0, padx=5, pady=5)
        self.category_entry = ttk.Entry(
            self.add_expense_window, justify="right", style="TEntry")
        self.category_entry.grid(row=0, column=1, padx=5, pady=5)
        # Label and entry field for the expense amount
        self.amount_label = ttk.Label(
            self.add_expense_window, text="Amount:", style="TLabel")
        self.amount_label.grid(row=1, column=0, padx=5, pady=5)
        self.amount_entry = ttk.Entry(
            self.add_expense_window, justify="right", style="TEntry")
        self.amount_entry.grid(row=1, column=1, padx=5, pady=5)
        # Label and date entry widget for the expense date
        self.date_label = ttk.Label(
            self.add_expense_window, text="Date:", style="TLabel")
        self.date_label.grid(row=2, column=0, padx=5, pady=5)
        self.date_cal = DateEntry(self.add_expense_window, background='darkblue',
                                  foreground='white', borderwidth=2, year=2023, month=11, day=14)  # Customize as needed
        self.date_cal.grid(row=2, column=1, padx=5, pady=5)
        # Button to submit the expense
        self.submit_button = ttk.Button(
            self.add_expense_window, text="Submit", command=self.submit_expense)
        self.submit_button.grid(row=3, column=0, columnspan=2, pady=10)
        # Button to go back/cancel the expense addition
        self.back_button = ttk.Button(
            self.add_expense_window, text="Back", command=self.add_expense_window.destroy)
        self.back_button.grid(row=4, column=0, columnspan=2, pady=10)

    def submit_expense(self):
        """ Process the submission of a new expense.
        This method retrieves entered expense details, validates them, and inserts the expense
        into the database. If successful, a success message is displayed, and the expense window
        is closed.
        Note: This method assumes the existence of certain attributes like user_id, budget,
        and get_total_expenses.
        """
        category = self.category_entry.get().strip()
        amount = self.amount_entry.get().strip()

        if not category.isalpha():
            # If the category contains non-alphabetic characters, show an error message.
            messagebox.showerror(
                "Error", "Category should only contain alphabets.")
            return

        try:
            # Convert the entered amount to a float.
            amount = float(amount)
        except ValueError:
             # If the entered amount is not a valid number, show an error message.
            messagebox.showerror("Error", "Amount should be a valid number.")
            return

        try:
            # Get the selected date from the date entry widget.
            date_obj = self.date_cal.get_date()
        except ValueError:
            # If the date format is invalid, show an error message.
            messagebox.showerror(
                "Error", "Invalid date format. Please use the calendar.")
            return

        if amount > self.budget - self.get_total_expenses():
            # If the expense exceeds the budget, show an error message.
            messagebox.showerror(
                "Budget Exceeded", "Expense exceeds the budget. Please adjust the amount.")
            return
        # Insert the expense into the database.
        cursor.execute('''
            INSERT INTO expenses (user_id, category, amount, date) VALUES (?, ?, ?, ?)
        ''', (self.user_id, category, amount, date_obj))
        conn.commit()
             # Show a success message and close the expense window.

        messagebox.showinfo("Success", "Expense added successfully.")
        self.add_expense_window.destroy()

    def get_total_expenses(self):
        """Retrieve the total expenses for the current user from the database.
        Returns:
        float: Total expenses for the current user.
        """
        df = pd.read_sql_query(
            f"SELECT * FROM expenses WHERE user_id={self.user_id}", conn)
        total_expense = df['amount'].sum()
        return total_expense

    def generate_report(self):
        if self.report_window is not None and self.report_window.winfo_exists():
            self.report_window.destroy()
        
        self.report_window = tk.Toplevel(self.root)
        self.report_window.title("Financial Report")
        # Create a Treeview widget for displaying expense details
        self.tree = ttk.Treeview(self.report_window, columns=(
            "Category", "Amount", "Date"), show="headings", style="Treeview")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Amount", text="Amount")
        self.tree.heading("Date", text="Date")
        # Label showing the total expense
        self.total_expense_label = ttk.Label(
            self.report_window, text=f"Total Expense: ₹0.00", style="TLabel")
        self.total_expense_label.pack(pady=10)
        # Label and Combobox for sorting the report by year
        self.sort_label = ttk.Label(
            self.report_window,
            text="Sort by Year:", style="TLabel")
        self.sort_label.pack(pady=10)

        self.sort_combobox = ttk.Combobox(
            self.report_window, values=self.get_year_options())
        self.sort_combobox.set("All Years")
        self.sort_combobox.pack(pady=5)
        self.sort_combobox.bind("<<ComboboxSelected>>", self.show_report)
        # Button for downloading the report as a CSV file
        self.download_button = ttk.Button(
            self.report_window, text="Download CSV", command=self.download_csv)
        self.download_button.pack(pady=10)
        # Display the initial report for all years
        self.show_report()

    def show_report(self, event=None):
        """ Display the financial report in the Treeview widget.
        This method retrieves and displays the expense details in the Treeview widget,
        taking into account the selected year for filtering.
        Note: This method assumes the existence of certain attributes like tree,
        total_expense_label, sort_combobox, download_button, and get_expenses_by_year.
        """
        self.tree.delete(*self.tree.get_children())
        total_expense = 0
        # Get the selected year from the Combobox
        selected_year = self.sort_combobox.get()
        # Retrieve expenses for the selected year
        df = self.get_expenses_by_year(selected_year)
         # Insert expense details into the Treeview widget
        for index, row in df.iterrows():
            self.tree.insert("", tk.END, values=(
                row['category'], row['amount'], row['date']))
            total_expense += row['amount']
        # Update the total expense label
        self.total_expense_label.config(
            text=f"Total Expense: ₹{total_expense:.2f}")
        # Pack the Treeview widget to display the report
        self.tree.pack(expand=tk.YES, fill=tk.BOTH)

    def get_expenses_by_year(self, selected_year):
        if selected_year == "All Years":
            return pd.read_sql_query(f"SELECT * FROM expenses WHERE user_id={self.user_id}", conn)
        else:
            # Calculate the start and end dates for the selected year
            start_date = datetime.strptime(
                f"January-{selected_year}", "%B-%Y").date()
            end_date = datetime.strptime(
                f"December-{selected_year}", "%B-%Y").date() + pd.DateOffset(days=31)
            # Retrieve expenses for the selected year from the database
            return pd.read_sql_query(
                f"SELECT * FROM expenses WHERE user_id={self.user_id} AND date BETWEEN '{start_date}' AND '{end_date}'", conn)

    def download_csv(self):
        """ Download the financial report as a CSV file.
        This method retrieves the expense details for the selected year and saves
        them, along with the total expense, into a CSV file. The user is prompted
        to choose the file location.
        Note: This method assumes the existence of certain attributes like
        sort_combobox and get_expenses_by_year.
        """
        # Get the selected year from the Combobox
        selected_year = self.sort_combobox.get()
         # Retrieve expenses for the selected year
        df = self.get_expenses_by_year(selected_year)

        if not df.empty:
            # Calculate the total expense
            total_expense = df['amount'].sum()
             # Add a row for the total expense in the DataFrame
            df = pd.concat([df, pd.DataFrame([['Total Expense', total_expense, '']], columns=[
                           'category', 'amount', 'date'])], ignore_index=True)
             # Prompt the user to choose the file location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if file_path:
                # Save the DataFrame to a CSV file
                df.to_csv(file_path, index=False)
                messagebox.showinfo("Success", "CSV file saved successfully.")
        else:
            # If no expenses, inform the user
            messagebox.showinfo("Info", "No expenses to download.")

    def get_year_options(self):
        """ Get the list of available years for filtering expenses.
        Returns:
        list: A list of years including "All Years" and unique years from the database.
        """
        # Retrieve all expenses from the database
        df = pd.read_sql_query("SELECT * FROM expenses", conn)
        if not df.empty:
            # Extract unique years from the date column
            years = pd.to_datetime(df['date']).dt.year.unique()
            # Return a list of years, including "All Years"
            return ["All Years"] + list(map(str, years))
        return ["All Years"]


if __name__ == "__main__":
    root = tk.Tk()
    app = PersonalFinanceManager(root)
    root.mainloop()

# Close the database connection when the application is closed
conn.close()
