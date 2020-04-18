'''it is an program which used to detect how much times your password has been hacked. it is totally secured because you use only five character of your hash password so you don't have to worry'''
import requests
import hashlib
import sys

# it takes the first five elements of our hash password and returns the response
def request_api_data(quarry):
    url = 'https://api.pwnedpasswords.com/range/' + quarry
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code},check the api and try again')
    return res

# it compare our hash password with diifrent hash password available and return the no. of times the password has been hacked
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

#it takes our password and convert it into hash one
def pwned_api_check(password):
    sha1password = str(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(str(first5_char))
    return get_password_leaks_count(response, tail)

#here we returns the no. of times password cames it runs our code through sys
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times .. you should probabily change your password')
        else:
            print(f'{password} was not found')
    return 'done'

#it runs if we run the main file and the code exists
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))