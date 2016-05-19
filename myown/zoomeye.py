import os

import requests

import json



access_token = ''

ip_list = []



def login():

	data = {

		'username' : 'nine.twelve@foxmail.com',

		'password' : '1995gundam*'

	}

	data_encoded = json.dumps(data)

	print data_encoded

	try:

		r = requests.post(url = 'http://api.zoomeye.org/user/login', data = data_encoded)

		r_decode = json.loads(r.text)

		print r_decode

		global access_token

		access_token = r_decode['access_token']

	except Exception, e:

		print '[-] info : username or password is wrong, please try again'

		exit()



def save_to_txt(ip):

	with open('target_test.txt', 'a+') as output:

		output.write(ip + '\n')

	

def search(target):

	page = 1

	global access_token

	with open('access_token.txt', 'r') as input:

		access_token = input.read()

		headers = {

		'Authorization' : 'JWT ' + access_token,					

		}

		while True:

			try:

				r = requests.get(url = 'http://api.zoomeye.org/web/search?query="' + target +\

						'"&facet=app,os&page=' + str(page), headers = headers)

				r_decoded = json.loads(r.text)

				#two keys : matches and total

				for x in r_decoded['matches']:

					print x['site']
					save_to_txt(x['site'])

			except  Exception,e:

				if str(e.message) == 'matches':

					print '[-] info : account was break, excceeding the max limitations'

					break

				else:

					print '[-] info : ' + str(e.message)

			else:

				if page == 10:

					break

				page += 1



def main():

	if not os.path.isfile('access_token.txt'):

		print '[-] info : access_token file is not exist, login...'

		login()

		with open('access_token.txt', 'w') as output:

			output.write(access_token)



	t = raw_input('please input your search\n>>>')

	search(t)	

main()




