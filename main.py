from mainWindow import Ui_MainWindow
from createAccount import Ui_CreateWindow
from profile import Ui_Profile
from settings import Ui_Settings
from profileDialog import Ui_ProfileDialog
from changePassword import Ui_ChangePassword
from deleteAccount import Ui_DeleteAccount
from PyQt5 import QtWidgets as qtw, QtGui as qtg, QtCore as qtc
import style
import sqlite3
import re
import bcrypt
import function as func

""" ******************************* MAIN WINDOW UI *******************************  """

class MainWindow(qtw.QWidget):
    def __init__(self):
        """The main window for the program."""
        super().__init__()

        self.ui_main = Ui_MainWindow()
        self.ui_main.setupUi(self)
        self.ui_main.label_error.hide()

        # Attempt
        self.attempt = 0
        self.timer = qtc.QTimer()

        # Timer
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.show_timer)

        # Counter
        self.counter = 11

        # Button Events
        self.ui_main.btn_create.clicked.connect(self.goto_create)
        self.ui_main.btn_login.clicked.connect(self.validate_account)

        # Cursor Changes
        self.ui_main.btn_create.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_main.btn_login.setCursor(qtc.Qt.PointingHandCursor)

    def lock_login(self):
        """ Locks the UI when the log in attempts failed n times. """
        if self.attempt == 4:
            self.timer.start()

            # Lock Buttons
            self.ui_main.btn_login.setEnabled(False)
            self.ui_main.btn_login.setStyleSheet(style.btn_grey)
            self.ui_main.btn_create.setEnabled(False)
            self.ui_main.btn_create.setStyleSheet(style.btn_grey)

            # Lock Line Edits
            self.ui_main.txt_username.setEnabled(False)
            self.ui_main.txt_password.setEnabled(False)

    def show_timer(self):
        """ Shows the timer for locking the UI. """
        self.ui_main.label_error.setText(f"Max attempt reached. Locking UI in {self.counter - 1}s")

        self.counter -= 1

        if self.counter == 0:
            self.timer.stop()
            self.end_timer()

    def end_timer(self):
        """ Refreshes the attempts and time values when the time ends. """
        self.ui_main.label_error.hide()
        self.attempt = 0
        self.counter = 11
        self.ui_main.btn_create.setStyleSheet(style.btn_orange)
        self.ui_main.btn_create.setEnabled(True)
        self.ui_main.btn_login.setEnabled(True)
        self.ui_main.btn_login.setStyleSheet(style.btn_orange)
        self.ui_main.txt_username.setEnabled(True)
        self.ui_main.txt_password.setEnabled(True)
        self.ui_main.txt_username.clear()
        self.ui_main.txt_password.clear()

    def goto_create(self):
        """Loads and open the create account UI."""
        widgets.setCurrentIndex(widgets.currentIndex() + 1)
        self.refresh_main()

    def validate_account(self):
        """Checks if the account exists and is valid."""

        username = self.ui_main.txt_username.text()
        password = self.ui_main.txt_password.text()

        # Check if the max attempt is exceeded
        self.lock_login()

        conn = sqlite3.connect("account.db")
        c = conn.cursor()
        c.execute(f"SELECT * FROM accounts WHERE username = '{username}'")

        db_data = c.fetchone()

        if func.check_empty(self.ui_main, style.label_red, username, password):
            return

        if not db_data:
            func.show_message(self.ui_main, "That username does not exist", style.label_red)
            return

        elif bcrypt.checkpw(password.encode("utf8"), db_data[2]):
            self.goto_profile(db_data[0], username)
        else:
            self.attempt += 1
            func.show_message(self.ui_main, "Invalid password", style.label_red)

        conn.commit()
        conn.close()

    def goto_profile(self, id, user):
        """Loads the profile UI."""
        self.ui_profile = Profile(id, user)
        widgets.addWidget(self.ui_profile)
        widgets.setCurrentIndex(widgets.currentIndex() + 2)
        self.refresh_main()

    def refresh_main(self):
        """Refreshes the main UI if the user jumps to profile or create account page."""
        self.ui_main.txt_username.setText("")
        self.ui_main.txt_password.setText("")
        self.ui_main.label_error.hide()

""" ******************************* CREATE ACCOUNT UI *******************************  """

class CreateWindow(qtw.QWidget):
    def __init__(self):
        """UI for creating an account for the program."""
        super().__init__()
        self.ui_create = Ui_CreateWindow()
        self.ui_create.setupUi(self)
        self.ui_create.label_error.hide()

        # Button Events
        self.ui_create.btn_back.clicked.connect(self.goto_main)
        self.ui_create.btn_create.clicked.connect(self.create_account)

        # Cursor Changes
        self.ui_create.btn_back.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_create.btn_create.setCursor(qtc.Qt.PointingHandCursor)

    def goto_main(self):
        """Goes back to the main UI."""
        self.refresh_widget()
        widgets.setCurrentIndex(widgets.currentIndex() - 1)

    def create_account(self):
        """Extracts string from the text edit objects."""

        #QLineEdit string variables
        username = self.ui_create.txt_user.text()
        password = self.ui_create.txt_pass.text()
        confirm = self.ui_create.txt_confirm.text()

        self.validate_entries(username, password, confirm)

    def validate_entries(self, username, password, confirm):
        """Validates the entries of the user."""

        #   Prompt messages when not validated
        user_prompt = "Invalid username, use alphanumeric characters or underscore \"_\". It must be at least 6 characters long"
        pass_prompt = "Invalid password, use alphanumeric characters only. It must be at least 8 characters long"

        # Regex patterns
        user_regex = "^[a-zA-Z0-9_]{6,}$"
        pass_regex = "^[a-zA-Z0-9]{8,}$"

        if func.check_empty(self.ui_create, style.label_red, username, password, confirm):
            return

        # Validate Username
        if not self.validate_string(user_regex, username, user_prompt):
            return

        # Validate Password
        if not self.validate_string(pass_regex, password, pass_prompt):
            return

        # Checks if the password is confirmed
        if not self.confirm_pass(password, confirm):
            return

        self.account_validated(username, password)

    def validate_string(self, regex, string, text):
        """Validates the username."""
        if not re.search(regex, string):
            func.show_message(self.ui_create, text, style.label_red)
            return False
        return True

    def account_validated(self, username, password):
        """Saves the account in the database when validated."""

        # Encrypt password
        salt = bcrypt.gensalt()
        hash_pw = self.hash_string(password, salt)

        # UI Feedback
        self.save_to_db(username, hash_pw)

    def hash_string(self,password, salt):
        """Hashes the password for the account."""
        temp = password.encode("utf8")
        return bcrypt.hashpw(temp, salt)

    def create_success(self):
        """Executes a feedback if the creation of an account is successful."""
        func.show_message(self.ui_create,
                          "The account has been created!\n Click \"BACK\" to sign in",
                          style.label_green)
        self.ui_create.btn_create.setEnabled(False)
        self.ui_create.txt_user.setEnabled(False)
        self.ui_create.txt_pass.setEnabled(False)
        self.ui_create.txt_confirm.setEnabled(False)
        self.ui_create.btn_create.setStyleSheet(style.btn_grey)
        self.ui_create.btn_back.setStyleSheet(style.btn_green)

    def refresh_widget(self):
        """Refreshes the UI for the create account"""
        self.ui_create.btn_create.setEnabled(True)
        self.ui_create.txt_user.setEnabled(True)
        self.ui_create.txt_pass.setEnabled(True)
        self.ui_create.txt_confirm.setEnabled(True)
        self.ui_create.btn_create.setStyleSheet(style.btn_orange)
        self.ui_create.btn_back.setStyleSheet(style.btn_orange)
        self.ui_create.txt_pass.setText("")
        self.ui_create.txt_user.setText("")
        self.ui_create.txt_confirm.setText("")
        self.ui_create.label_error.hide()
        self.ui_create.label_error.setStyleSheet(style.label_red)

    def confirm_pass(self, password, confirm):
        """Validates if the password is confirmed."""
        if password == confirm:
            self.ui_create.label_error.hide()
            return True
            
        func.show_message(self.ui_create,"The passwords do not match", style.label_red)
        return False

    def save_to_db(self, username, password):
        """Stores the information into a database."""
        # Try except to check for duplicates
        try:
            conn = sqlite3.connect('account.db')
            c = conn.cursor()
            c.execute(
                "INSERT INTO accounts (username, password) VALUES (?,?)",
                (username, password)
            )
            conn.commit()
            conn.close()

            conn_key = sqlite3.connect("pass.db")
            ck = conn_key.cursor()
            ck.execute("INSERT INTO pk (pw) VALUES (?)", (func.generate_key(),))
            conn_key.commit()
            conn_key.close()

            self.create_success()
        except sqlite3.IntegrityError:
            func.show_message(self.ui_create, "That username already exists.", style.label_red)

""" ******************************* USER PROFILE UI *******************************  """

class Profile(qtw.QWidget):
    def __init__(self, id, user):
        """UI for the user's account."""
        super().__init__()
        self.ui_profile = Ui_Profile()
        self.ui_profile.setupUi(self)
        self.id = id
        self.user = user
        self.key = self.get_key()
        self.greet_user()
        self.profile = self
        self.entries = []

        self.form_layout = qtw.QFormLayout()
        self.group_box = qtw.QGroupBox()
        self.group_box.setLayout(self.form_layout)

        # Scroll area attributes
        self.scroll = self.ui_profile.container
        self.scroll.setWidget(self.group_box)
        self.scroll.setWidgetResizable(True)

        # Button Events
        self.flag = False
        self.ui_profile.btn_setting.clicked.connect(self.goto_settings)
        self.ui_profile.btn_logout.clicked.connect(self.logout)
        self.ui_profile.btn_add.clicked.connect(self.goto_prof_dialog)
        self.ui_profile.btn_show.clicked.connect(self.fetch_entries)

        # Cursor Changes
        self.ui_profile.btn_setting.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_profile.btn_setting.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_profile.btn_add.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_profile.btn_show.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_profile.btn_show.setCursor(qtc.Qt.PointingHandCursor)

    def get_key(self):
        """ Returns the key for the decryption. """
        conn_key = sqlite3.connect("pass.db")
        ck = conn_key.cursor()
        ck.execute(
            f"""
                SELECT * FROM pk WHERE id = (?)
            """, (self.id,)
        )
        db_key = ck.fetchone()[1]
        return db_key

    def greet_user(self):
        """Greets the user when they log in."""
        self.ui_profile.label_greet.setText(f"Welcome, {self.user}!")

    def goto_prof_dialog(self):
        """ Shows the dialog window when the add button is clicked. """
        self.profile_dialog = ProfileDialog(self.id, self.user, self.key, self)
        widgets.addWidget(self.profile_dialog)
        widgets.setCurrentIndex(widgets.currentIndex() + 1)

    def logout(self):
        """Logs out of the account and deletes the current profile object."""
        qtw.QStackedWidget.removeWidget(widgets, self)
        widgets.setCurrentIndex(0)

    def goto_settings(self):
        """Jumps to the profile setting UI."""
        self.settings = Settings(self.user, self.profile, self.id)
        widgets.addWidget(self.settings)
        widgets.setCurrentIndex(widgets.currentIndex() + 1)

    def fetch_entries(self):
        """ Fetch the data corresponding to the primary key. """
        conn = sqlite3.connect("account.db")
        c = conn.cursor()
        self.entries = c.execute("""
                SELECT * FROM entries WHERE user_entryid = (?)
            """, (self.id,)
        ).fetchall()

        key = self.get_key()
        self.flag = not self.flag

        if self.flag:
            self.ui_profile.btn_show.setText("Hide Accounts")
            self.show_entries(key)
        else:
            self.entries = []
            self.ui_profile.btn_show.setText("Show Accounts")
            for i in reversed(range(self.form_layout.count())):
                self.form_layout.itemAt(i).widget().setParent(None)

    def show_entries(self, key):
        """ Shows the entries in the scroll area."""
        for i, entry in enumerate(self.entries):
            app = entry[1]
            username = entry[2]
            temp_str = f"{entry[1]}{entry[2]}"
            password = func.decrypt_pass(entry[3], temp_str, key)

            # Delete Button
            btn_delete = qtw.QPushButton()
            btn_delete.setText("Delete Entry")
            btn_delete.setStyleSheet(style.btn_delete)
            btn_delete.setFixedHeight(60)
            btn_delete.setFixedWidth(140)
            btn_delete.clicked.connect(lambda checked, i=i: self.delete_entry(i))
            btn_delete.setCursor(qtc.Qt.PointingHandCursor)

            # Text
            label = f"""&nbsp;&nbsp;{i+1}.) <b>{app}</b> <br/>
                    <span style = "color : #00255f">{style.tab}<i>USERNAME :</i> {username}</span><br/>
                    <span style = "color : #00255f">{style.tab}<i>PASSWORD :</i></span>
                    <span style = "color: #ff0000"> {password}<span>"""

            row = qtw.QLabel(label)
            row.setTextFormat(qtc.Qt.RichText)
            row.setStyleSheet(style.entries_text)
            row.setFont(qtg.QFont('Arial', 14))
            row.setFixedWidth(425)
            row.setTextInteractionFlags(qtc.Qt.TextSelectableByMouse)
            row.setCursor(qtc.Qt.IBeamCursor)
            self.form_layout.addRow(row, btn_delete)

    def delete_entry(self, i):
        """ Deletes the entry from the entries table of the database. """
        message_box = qtw.QMessageBox()
        message_box.setStyleSheet("background-color: #2b5b84; color: white;")
        answer = message_box.question(self, "Delete Entry",
                                      f"Are you sure you want to delete {self.entries[i][1]}?",
                                      message_box.Yes | message_box.No)

        if answer == message_box.Yes:
            conn = sqlite3.connect("account.db")
            c = conn.cursor()
            c.execute(
            f""" 
                DELETE FROM entries 
                WHERE appname = '{self.entries[i][1]}' 
                AND appuser = '{self.entries[i][2]}'
                AND apppass = (?)
            """,(self.entries[i][3],)
            )

            conn.commit()
            conn.close()
            self.refresh_scrollarea()
        else:
            return

    def refresh_scrollarea(self):
        """ Calls the fetch function twice to refresh the scroll area. """
        for _ in range(2):
            self.fetch_entries()

""" ******************************* PROFILE SETTINGS UI *******************************  """

class Settings(qtw.QWidget):
    def __init__(self, user, profile, id):
        """UI for profile settings"""
        super().__init__()
        self.ui_settings = Ui_Settings()
        self.ui_settings.setupUi(self)
        self.user = user
        self.profile = profile
        self.id = id
        self.settings = self

        # Label Event
        self.ui_settings.label_user_acc.setText(f"Account: {self.user}")

        # Button Events
        self.ui_settings.btn_change_pw.clicked.connect(self.goto_change)
        self.ui_settings.btn_delete_acc.clicked.connect(self.goto_delete)
        self.ui_settings.btn_back.clicked.connect(self.goto_profile)

        # Cursor Changes
        self.ui_settings.btn_change_pw.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_settings.btn_delete_acc.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_settings.btn_back.setCursor(qtc.Qt.PointingHandCursor)

    def goto_profile(self):
        """Jumps back to the profile UI."""
        qtw.QStackedWidget.removeWidget(widgets, self)
        widgets.setCurrentIndex(2)

    def goto_change(self):
        """Jumps to the change password UI for the account."""
        self.ui_change_pass = ChangePassword(self.user)
        widgets.addWidget(self.ui_change_pass)
        widgets.setCurrentIndex(widgets.currentIndex() + 1)

    def goto_delete(self):
        """Jumps to the delete account UI."""
        self.ui_del_acc = DeleteAccount(self.user, self.profile, self.settings, self.id)
        widgets.addWidget(self.ui_del_acc)
        widgets.setCurrentIndex(widgets.currentIndex() + 1)

""" ******************************* CHANGE PASSWORD UI *******************************  """

class ChangePassword(qtw.QWidget):
    def __init__(self, user):
        """UI for changing password in the settings."""
        super().__init__()
        self.ui_change_pass = Ui_ChangePassword()
        self.ui_change_pass.setupUi(self)
        self.ui_change_pass.label_error.hide()
        self.user = user
        self.ui_change_pass.label_user_acc.setText(f"Account: {self.user}")
        self.pattern = "^[a-zA-Z0-9]{8,}$"

        # Button Event
        self.ui_change_pass.btn_back.clicked.connect(self.goto_settings)
        self.ui_change_pass.btn_change_pw.clicked.connect(self.input_new_pass)

        # Cursor Changes
        self.ui_change_pass.btn_back.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_change_pass.btn_change_pw.setCursor(qtc.Qt.PointingHandCursor)

    def input_new_pass(self):
        conn = sqlite3.connect("account.db")
        c = conn.cursor()
        c.execute(f'SELECT * FROM accounts WHERE username = "{self.user}"')
        db_data = c.fetchone()[2]

        password = self.ui_change_pass.txt_pass.text()
        new_pass = self.ui_change_pass.txt_new_pass.text()
        confirm = self.ui_change_pass.txt_confirm.text()
        pass_prompt = "Invalid password, use alphanumeric characters only. It must be at least 8 characters long"

        # If the fields are empty
        if func.check_empty(self.ui_change_pass, style.label_red, password, new_pass, confirm):
            return

        # If the new password is noe in tht correct format.
        if not bcrypt.checkpw(password.encode("utf8"), db_data):
            func.show_message(self.ui_change_pass, "The password is incorrect", style.label_red)
            return
        else:
            if not self.validate_string(new_pass, pass_prompt):
                return
            elif password == new_pass and password == confirm:
                func.show_message(self.ui_change_pass, "Please enter a NEW password", style.label_red)
            elif confirm == new_pass:
                self.change_pass(new_pass, c)
                self.pw_changed()
            else:
                func.show_message(self.ui_change_pass, "The new password and confirm password do not match", style.label_red)

        conn.commit()
        conn.close()

    def change_pass(self, new_pass, c):
        """ Changes the hash value in the database with the new one. """
        # Encrypt password
        salt = bcrypt.gensalt()
        temp = new_pass.encode("utf8")
        hash_pw = bcrypt.hashpw(temp, salt)

        c.execute(f' UPDATE accounts SET password = (?) WHERE username = "{self.user}"', (hash_pw,))

    def validate_string(self, string, text):
        """Validates the username if the string is in the correct format."""
        if not re.search(self.pattern, string):
            func.show_message(self.ui_change_pass, text, style.label_red)
            return False
        return True

    def pw_changed(self):
        """Sets the UI into a success state after changing the password."""
        func.show_message(self.ui_change_pass, "The password has been changed!", style.label_green)
        self.ui_change_pass.btn_back.setStyleSheet(style.btn_green)
        self.ui_change_pass.btn_change_pw.setStyleSheet(style.btn_grey)
        self.ui_change_pass.btn_change_pw.setEnabled(False)

    def goto_settings(self):
        """Goes back to the account setting page."""
        qtw.QStackedWidget.removeWidget(widgets, self)
        widgets.setCurrentIndex(3)

""" ******************************* CHANGE PASSWORD UI *******************************  """

class DeleteAccount(qtw.QWidget):
    def __init__(self, user, profile, settings, id):
        """UI for deleting the user's account in the setting page."""
        super().__init__()
        self.ui_delete_acc = Ui_DeleteAccount()
        self.ui_delete_acc.setupUi(self)
        self.user = user
        self.id = id
        self.ui_delete_acc.label_user_acc.setText(f"Account: {self.user}")
        self.profile = profile
        self.settings = settings

        # Button Events
        self.ui_delete_acc.btn_back.clicked.connect(self.goto_settings)
        self.ui_delete_acc.btn_del_acc.clicked.connect(self.confirm_pass)

        # Cursor Changes
        self.ui_delete_acc.btn_back.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_delete_acc.btn_del_acc.setCursor(qtc.Qt.PointingHandCursor)

    def goto_settings(self):
        """Goes back to the account setting page."""
        qtw.QStackedWidget.removeWidget(widgets, self)
        widgets.setCurrentIndex(3)

    def delete_account(self):
        """Deletes the account if the password is correct."""
		
        # SQLite3 actions.
        conn = sqlite3.connect("account.db")
        c = conn.cursor()
        c.execute("PRAGMA foreign_keys = ON")
        c.execute(f"DELETE FROM accounts WHERE username ='{self.user}'")
        conn.commit()
        conn.close()

        conn_key = sqlite3.connect("pass.db")
        ck = conn_key.cursor()
        ck.execute(f"DELETE FROM pk WHERE id = (?)", (self.id,))
        conn_key.commit()
        conn_key.close()

        self.return_to_main()

    def return_to_main(self):
        """ Removes the profile and the settings from the stack widget then returns to the main UI. """
        qtw.QStackedWidget.removeWidget(widgets, self)
        qtw.QStackedWidget.removeWidget(widgets, self.profile)
        qtw.QStackedWidget.removeWidget(widgets, self.settings)

        widgets.setCurrentIndex(0)

    def confirm_pass(self):
        """Verifies the account deletion."""
        confirm = self.ui_delete_acc.txt_confirm.text()
        password = self.ui_delete_acc.txt_pass.text()

        conn = sqlite3.connect("account.db")
        c = conn.cursor()
        c.execute(f"SELECT * FROM accounts WHERE username = '{self.user}'")

        db_data = c.fetchone()[2]

        conn.commit()
        conn.close()

        if func.check_empty(self.ui_delete_acc, style.label_red, confirm, password):
            func.show_message(self.ui_delete_acc, "Please enter fields", style.label_red)
            return

        if bcrypt.checkpw(password.encode("utf8"), db_data):
            if password == confirm:
                self.delete_account()
            else:
                func.show_message(self.ui_delete_acc, "The passwords do not match", style.label_red)
                return
        else:
            func.show_message(self.ui_delete_acc, "The password is incorrect", style.label_red)
            return

    def refresh_page(self):
        """Refreshes the page when the user exits delete account page."""
        self.ui_delete_acc.txt_pass.setText("")
        self.ui_delete_acc.txt_confirm.setText("")
        self.ui_delete_acc.label_error.setStyleSheet(style.label_green)
        self.ui_delete_acc.label_error.setText("Please type your password again to confirm")

""" ***************************** PROFILE DIALOG WINDOW *******************************  """

class ProfileDialog(qtw.QWidget):
    def __init__(self, id, user, key, profile):
        """ Profile dialog attribute when adding an account in the scroll area. """
        super().__init__()
        self.user = user
        self.id = id
        self.profile = profile
        self.key = key
        self.ui_prof_dialog = Ui_ProfileDialog()
        self.ui_prof_dialog.setupUi(self)
        self.ui_prof_dialog.label_error.hide()
        self.ui_prof_dialog.label_main.setText(f"ADD  AN  ENTRY  FOR  USER : {self.user}")

        # Button Event
        self.ui_prof_dialog.btn_generate.clicked.connect(self.generate_pass)
        self.ui_prof_dialog.btn_back.clicked.connect(self.goto_profile)
        self.ui_prof_dialog.btn_save.clicked.connect(self.save_entry)

        # Cursor Changes
        self.ui_prof_dialog.btn_generate.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_prof_dialog.btn_back.setCursor(qtc.Qt.PointingHandCursor)
        self.ui_prof_dialog.btn_save.setCursor(qtc.Qt.PointingHandCursor)

    def goto_profile(self):
        """ Goes back to the profile page when the BACK button is pressed. """
        qtw.QStackedWidget.removeWidget(widgets, self)
        self.destroy()
        widgets.setCurrentIndex(2)
        self.profile.refresh_scrollarea()

    def generate_pass(self):
        """ Generates a password using random library. """
        gen_pass = func.generate_pass()
        self.ui_prof_dialog.txt_pass.setText(gen_pass)

    def save_entry(self):
        """ Validates the text fields then save if they are filled. """
        ui = self.ui_prof_dialog
        password = self.ui_prof_dialog.txt_pass.text()
        username = self.ui_prof_dialog.txt_user.text()
        account = self.ui_prof_dialog.txt_account.text()

        if func.check_empty(ui, style.label_red, password, username, account):
            return
        else:
            prompt = "The account has been saved!"
            self.ui_prof_dialog.btn_back.setStyleSheet(style.btn_green)
            self.disable_button()
            func.show_message(self.ui_prof_dialog, prompt, style.label_green)
            self.save_to_db(account, username, password)

    def disable_button(self):
        """ Disabled the BACK and GENERATE button upon a successful entry. """
        self.ui_prof_dialog.btn_save.setStyleSheet(style.btn_grey)
        self.ui_prof_dialog.btn_generate.setStyleSheet(style.btn_grey)
        self.ui_prof_dialog.btn_save.setEnabled(False)
        self.ui_prof_dialog.btn_generate.setEnabled(False)

    def save_to_db(self, acc, user, pw):
        """ Saves the entries in the database. """
        conn = sqlite3.connect("account.db")
        c = conn.cursor()
        c.execute(
            """ 
                INSERT INTO entries (
                    user_entryid, appname,
                    appuser, apppass
                ) 
                VALUES (?,?,?,?)
            """, (self.id, acc, user, func.encrypt_pass(pw, f"{acc}{user}", self.key))
        )
        conn.commit()
        conn.close()

""" ******************************* GLOBAL BLOCK *******************************  """

if __name__ == "__main__":
    app = qtw.QApplication([])
    app.setWindowIcon(qtg.QIcon(qtg.QPixmap("./images/window_icon.png")))

    # Main Window
    main_widget = MainWindow()
    main_widget.show()

    # Create Window to be added in the stack widget
    create_widget = CreateWindow()

    # Create database for the program if it doesn't exist yet
    conn = sqlite3.connect('account.db')
    c = conn.cursor()

    # PARENT TABLE
    c.execute(
        """
            CREATE TABLE IF NOT EXISTS accounts (
                userid INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password BLOB
            )
        """
    )

    # CHILD TABLE
    c.execute(
        """
            CREATE TABLE IF NOT EXISTS entries(
                user_entryid INTEGER,
                appname TEXT,
                appuser TEXT,
                apppass TEXT,
                FOREIGN KEY (user_entryid) 
                    REFERENCES accounts(userid) 
                    ON DELETE CASCADE
            )
        """
    )

    # KEY
    conn_key = sqlite3.connect("pass.db")
    ck = conn_key.cursor()
    ck.execute(
        """
            CREATE TABLE IF NOT EXISTS pk(
            id INTEGER PRIMARY KEY,
            pw BLOB
        )
        """
    )

    conn_key.commit()
    conn_key.close()
    conn.commit()
    conn.close()

    # Stack Widgets table of contents
    """ 
        widgets[0] : main window,
        widgets[1] : create account,
        widgets[2] : profile 
        widgets[3] : profile dialog, settings
        widgets[4] : delete account, change password
    """

    widgets = qtw.QStackedWidget()
    widgets.addWidget(main_widget)
    widgets.addWidget(create_widget)
    widgets.setWindowFlags(qtc.Qt.WindowCloseButtonHint | qtc.Qt.WindowMinimizeButtonHint)
    widgets.setFixedWidth(596)
    widgets.setFixedHeight(743)
    widgets.setWindowTitle("Password Vault")
    widgets.setStyleSheet(style.widget_css)
    widgets.show()

    # Executes the program
    app.exec_()
