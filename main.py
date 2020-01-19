from kivy.app import App
from kivy.lang import Builder
from kivy.properties import ObjectProperty
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen

from databaseAndCrypto import DatabaseAndCrypto # Local module 

passwordPlain = ""


class WindowManager(ScreenManager):
    pass


class CreateAccountWindow(Screen):
    namee = ObjectProperty(None)
    password = ObjectProperty(None)

    def submit(self):
        if self.namee.text != "":
            if self.password != "":
                add_userOutput = db.add_user(self.namee.text, self.password.text)
                if add_userOutput:
                    self.reset()
                    wm.current = "login"
                    show_popup('Account added successfully', 'Enjoy your account.')
                else:
                    # invalidUsername()
                    show_popup('Username already taken',
                               'Please change your username.')

            else:
                # invalidForm()
                show_popup('Incorrect data', 'Please fill form with correct data.')
        else:
            # invalidForm()
            show_popup('Incorrect data', 'Please fill form with correct data.')

    def login(self):
        self.reset()
        wm.current = "login"

    def reset(self):
        self.password.text = ""
        self.namee.text = ""


class LoginWindow(Screen):
    userName = ObjectProperty(None)
    password = ObjectProperty(None)

    # global passwordPlain

    def login_btn(self):
        global passwordPlain

        if db.validate_login(self.userName.text, self.password.text):
            MainWindow.current = self.userName.text
            passwordPlain = self.password.text
            # print('self.passwordPlain ' + passwordPlain)
            self.reset()
            wm.current = "main"

            # print("Passwordplain ", passwordPlain)
        else:
            # invalidLogin()
            show_popup('Invalid Login data', 'Incorrect username or password.')

    def create_btn(self):
        self.reset()
        wm.current = "create"

    def reset(self):
        self.userName.text = ""
        self.password.text = ""


class MainWindow(Screen):
    userName = ObjectProperty(None)
    current = ""

    @staticmethod
    def log_out():
        wm.current = "login"

    def on_enter(self, *args):
        self.userName.text = f"Logged as: {self.current}"

    def add_password(self):
        AddPassword.current = self.current

    def get_password(self):
        GetPassword.current = self.current

    def update_password(self):
        UpdatePassword.current = self.current


class AddPassword(Screen):
    service = ObjectProperty(None)
    password = ObjectProperty(None)
    userName = ObjectProperty(None)
    current = ""

    def add_password(self):
        encryptedPassword = db.encrypt_password(self.current, self.password.text, passwordPlain)
        addOutput = db.add_password(self.service.text, self.current, encryptedPassword)
        # print('addOutput ', addOutput)
        if addOutput:
            show_popup("Password has been added.", "Your password has been added successfully.")
            self.reset()
        elif not addOutput:
            show_popup('Password to this service is already saved.',
                       'If you want to change this password, update it.')

    def on_enter(self, *args):
        self.userName.text = f"Logged as: {self.current}"

    def reset(self):
        self.service.text = ""
        self.password.text = ""


class GetPassword(Screen):
    service = ObjectProperty(None)
    password = ObjectProperty(None)
    userName = ObjectProperty(None)
    current = ""

    # def __init__(self, **kwargs):
    #     super(GetPassword, self).__init__(**kwargs)
    #     # global passwordPlain
    #
    #     # self.passwordPlainL = passwordPlain
    def reset(self):
        self.service.text = ""
        self.password.text = ""

    def on_enter(self, *args):
        self.userName.text = f"Logged as: {self.current}"
        global passwordPlain
        self.passwordPlainL = passwordPlain
        # print(self.current)
        # print("popop " + self.passwordPlainL)

    def get_password(self):
        # password_service = db.get_encrypted_password(self.service.text, self.current)[0]
        # print(self.passwordPlainL)
        password_service = db.get_encrypted_password(self.service.text, self.current)
        # print('password_service', password_service)
        if password_service:
            plainServicePassword = db.decrypt_password(self.current, password_service[0], self.passwordPlainL)
            self.password.text = plainServicePassword
        # print(plainServicePassword)
        else:
            show_popup("You don't have a saved password for this service",
                       "You can add a new password to this service.")
            self.reset()

    def get_all_services(self):
        allServicesRaw = db.get_all_services(self.current)
        allServices = []

        for record in allServicesRaw:
            allServices.append(record[0])
        separator = ', '
        self.password.text = separator.join(allServices)

    def check_choice(self):
        if self.service.text == "*":
            self.get_all_services()
        else:
            self.get_password()


class UpdatePassword(Screen):
    service = ObjectProperty(None)
    userName = ObjectProperty(None)
    password = ObjectProperty(None)
    current = ""

    def reset(self):
        self.service.text = ""
        self.password.text = ""

    def on_enter(self, *args):
        self.userName.text = f"Logged as: {self.current}"

    def update_password(self):
        global passwordPlain
        encryptedPassword = db.encrypt_password(self.current, self.password.text, passwordPlain)
        # print(encryptedPassword)
        db.update_encrypted_password(self.service.text, self.current, encryptedPassword)
        show_popup('Password updated successfully', 'Password updated successfully')
        self.reset()


# class CopyPassword(TextInput):
#     def on_double_tap(self):
#         password = self.select_all()
#         pyperclip.copy(str(password))


# def invalidLogin():
#     pop = Popup(title='Błędny Login',
#                   content=Label(text='Błędna nazwa użytkownika lub hasło'),
#                   size_hint=(None, None), size=(400, 400))
#     pop.open()


# def invalidForm():
#     pop = Popup(title='Błędne dane',
#                   content=Label(text='Proszę uzupełnij formularz poprawnymi danymi.'),
#                   size_hint=(None, None), size=(400, 400))
#
#     pop.open()
#
# def invalidUsername():
#     pop = Popup(title='Nazwa użytkownika jest już zajęta',
#                   content=Label(text='Proszę wpisz inną wyjątkową nazwę użytkownika.'),
#                   size_hint=(None, None), size=(400, 400))
#
#     pop.open()
def show_popup(myTitle, myContent):
    pop = Popup(title=myTitle, content=Label(text=myContent),
                size_hint=(None, None), size=(400, 400))
    pop.open()


kv = Builder.load_file("my.kv")
wm = WindowManager()
db = DatabaseAndCrypto()

screens = [LoginWindow(name="login"), CreateAccountWindow(name="create"), MainWindow(name="main"),
           AddPassword(name="add"), GetPassword(name="get"), UpdatePassword(name="update")]
# screens = [CreateAccountWindow(name="create")]


for screen in screens:
    wm.add_widget(screen)

wm.current = "login"


class MyMainApp(App):
    def build(self):
        self.title = "Password Manager"
        return wm


if __name__ == "__main__":
    MyMainApp().run()
