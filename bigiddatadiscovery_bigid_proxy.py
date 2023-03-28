# File: bigid_proxy.py
#
# Copyright (c) 2023 BigID
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import json

import requests


class BigidProxy:
    def __init__(self, bigid_url, bigid_token, *args, **kwargs):
        self.bigid_url = bigid_url
        self.bigid_token = bigid_token
        self.headers = {
            'Content-type': 'application/json; charset=UTF-8',
            'Authorization': bigid_token
        }
        payload = kwargs.get('payload', None)
        print(payload)

    def get_request(self, endpoint):
        return requests.get(self.bigid_url + endpoint, headers=self.headers, verify=False)

    def post_request(self, endpoint, payload):
        return requests.post(self.bigid_url + endpoint, headers=self.headers, verify=False, data=payload)

    def put_request(self, endpoint, payload):
        return requests.put(self.bigid_url + endpoint, headers=self.headers, verify=False, data=payload)

    def refresh_token(self):
        # nosemgrep
        response = requests.get(self.bigid_url + 'refresh-access-token', headers=self.headers, verify=False)
        data = json.loads(response.text)
        self.headers['Authorization'] = data['systemToken']
        return data['systemToken']

    @staticmethod
    def generate_response(execution_id, status_enum, progress, message):
        response = {'executionId': execution_id, 'statusEnum': status_enum,
                    'progress': progress, 'message': message}
        return response
