class UI:
    @staticmethod
    def main_menu():
        print('============')
        print('PassMan v0.1')
        print('============')
        print('1) Search for a login')
        print('2) Show all logins')
        print('3) Add a new login')
        print('4) Update a login')
        print('5) Delete a login')
        print('6) Exit')
        return input('What would you like to do? ')

    @staticmethod
    def search_login():
        return input('Enter the service you want to search for: ')

    @staticmethod
    def show_logins(logins):
        print('======================================================================')
        print('Index |        Service        |      Username      |     Password     ')
        print('======================================================================')
        for index, login in enumerate(logins):
            print(f'{index}     | {login.service:20} | {login.username:20} | {login.password:20}')

    @staticmethod
    def login_input():
        login = {}
        login.username = input('Enter the username: ')
        login.password = input('Enter the password: ')
        login.service = input('Enter the service: ')

    @staticmethod
    def error_message(errcode):
        if errcode == 1:
            print('No login found')
        elif errcode == 2:
            print('Invalid choice')
        elif errcode == 3:
            print('Login already exists. Please update or delete the existing login instead')
        else:
            print('Unknown error. You are on your own now. Good luck!')
