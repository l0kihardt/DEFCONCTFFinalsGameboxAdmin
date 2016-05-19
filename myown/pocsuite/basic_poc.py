#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite.net import req
from pocsuite.poc import Output, POCBase
from pocsuite.utils import register


class TestPOC(POCBase):
    vulID = 'example'  # vul ID
    version = '1'
    author = 'test'
    vulDate = '2016-05-16'
    createDate = '2016-05-16'
    updateDate = '2016-05-16'
    references = ['http://drops.wooyun.org/']
    name = 'test'
    appPowerLink = 'www.test.org'
    appName = 'test'
    appVersion = '1.0'
    vulType = 'Information Disclosure'
    desc = '''
		author = lowkey
	'''
    # the sample sites for examine
    samples = ['http://www.google.com']
  
    def _attack(self):
		#get attack
        response = req.get(self.url, timeout=10, headers={'123': '23'})
        return self.parse_attack(response)

    def _verify(self):
        return self._attack()

    def parse_attack(self, response):
        output = Output(self)
        result = {}
        if response:
            result['FileInfo'] = {}
            result['FileInfo']['Filename'] = response
            result['FileInfo']['Filecontent'] = 'test123' * 10
            output.success(result)
        else:
            output.fail('Internet Nothing returned')
        return output


register(TestPOC)
