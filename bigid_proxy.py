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
        response = requests.get(self.bigid_url + 'refresh-access-token', headers=self.headers, verify=False)
        data = json.loads(response.text)
        self.headers['Authorization'] = data['systemToken']
        return data['systemToken']

    @staticmethod
    def generate_response(execution_id, status_enum, progress, message):
        response = {'executionId': execution_id, 'statusEnum': status_enum,
                    'progress': progress, 'message': message}
        return response
