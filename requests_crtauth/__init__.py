# -*- coding: utf-8 -*-
"""HTTP crtauth authentication using the requests library."""

import logging
import os
import urlparse

from crtauth import ssh as crtauth_ssh
from crtauth import server as crtauth_server
import requests


class HttpCrtAuth(requests.auth.AuthBase):
    def __init__(self, username=None, private_key=None, signer=None):
        self.username = username or os.environ.get('USER')
        if private_key:
            self.signer = crtauth_ssh.SingleKeySigner(private_key)
        else:
            self.signer = signer
        self.original_request = None
        self.adapter = requests.adapters.HTTPAdapter()

    def parse_chap_header(self, headers):
        return [s.strip() for s in headers['X-CHAP'].split(':', 1)]

    def send_challenge_request(self, http_request, **kwargs):
        logging.debug('Sending challenge request')
        parsed_url = urlparse.urlparse(http_request.url)
        parsed_auth_url = urlparse.ParseResult(parsed_url.scheme,
                                               parsed_url.netloc,
                                               '/_auth',
                                               parsed_url.params,
                                               parsed_url.query,
                                               parsed_url.fragment)
        http_request.method = 'HEAD'
        http_request.headers['X-CHAP'] = 'request:%s' % self.username
        http_request.url = parsed_auth_url.geturl()
        http_response = self.adapter.send(http_request, **kwargs)
        return http_response

    def send_challenge_response(self, http_request, chap_challenge, **kwargs):
        logging.debug('Sending response to challenge %s', chap_challenge)
        server_name = urlparse.urlparse(http_request.url).netloc.split(':')[0]
        challenge_response = crtauth_server.create_response(chap_challenge,
                                                            server_name,
                                                            self.signer)
        http_request.method = 'HEAD'
        http_request.headers['X-CHAP'] = 'response:%s' % challenge_response
        http_response = self.adapter.send(http_request, **kwargs)
        return http_response

    def authenticated_request(self, http_request, chap_token, **kwargs):
        logging.debug('Authenticating using token %s', chap_token)
        http_request.headers['Authorization'] = 'chap:%s' % chap_token
        http_response = self.adapter.send(http_request, **kwargs)
        return http_response

    def response_handler(self, response, **kwargs):
        if response.status_code == 401:
            self.original_request = copy_request(response.request)
            challenge_response = self.send_challenge_request(
                response.request, **kwargs)
            challenge_response.history.append(response)
            self.response_handler(challenge_response, **kwargs)
        if 'X-CHAP' in response.headers:
            chap_key, chap_value = self.parse_chap_header(response.headers)
            if chap_key == 'challenge':
                challenge_response = self.send_challenge_response(
                    response.request, chap_value, **kwargs)
                challenge_response.history.append(response)
                self.response_handler(challenge_response, **kwargs)
            if chap_key == 'token':
                authenticated_response = self.authenticated_request(
                    self.original_request, chap_value, **kwargs)
                authenticated_response.history.append(response)
                return authenticated_response
        return response

    def __call__(self, request):
        request.register_hook('response', self.response_handler)
        return request


def copy_request(request):
    """Copies a PreparedRequest."""
    new_request = requests.PreparedRequest()

    new_request.method = request.method
    new_request.url = request.url
    new_request.body = request.body
    new_request.hooks = request.hooks
    new_request.headers = request.headers.copy()

    return new_request
