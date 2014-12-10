# -*- coding: utf-8 -*-
"""HTTP crtauth authentication using the requests library."""

import logging
import os
import urlparse

from crtauth import ssh as crtauth_ssh
from crtauth import server as crtauth_server
import requests


class HttpCrtAuthError(requests.exceptions.RequestException):
    """Raised when Crt Authentication fails."""


class HttpCrtAuth(requests.auth.AuthBase):
    def __init__(self, username=None, private_key=None, signer=None):
        """HTTP crtauth authentication using the requests library.

        Args:
            username: User to authenticate as. Defaults to $USER.
            private_key: A PEM encoded private key string. Overrides signer.
            signer: A crtauth SigningPlug instance. Defaults to using the
                SSH agent (AgentSigner).
        """
        self.username = username or os.environ.get('USER')
        if private_key:
            self.signer = crtauth_ssh.SingleKeySigner(private_key)
        else:
            self.signer = signer
        self.chap_token = None

    def _parse_chap_header(self, headers):
        """Parses the X-CHAP header.

        CHAP headers are encoded like:
            X-CHAP:request:negz
            X-CHAP:challenge:butts
            X-CHAP:response:moo
            X-CHAP:token:zomgauthentication

        Each HTTP request or response should have a single X-CHAP header.

        Args:
            headers: A case insensitive dictionary of HTTP headers.

        Returns:
            A tuple like (chap_header_key, chap_header_value).
        """
        return tuple([s.strip() for s in headers['X-CHAP'].split(':', 1)])

    def _challenge_request(self, response, **kwargs):
        """Forms a CHAP request based on a real PreparedRequest.

        Args:
            response: The original 401 requests.Response() instance.
            **kwargs: Keyword arguments to pass with subsequent requests.

        Returns:
            An instance of requests.Response() with the appropriate
                'X-CHAP:challenge' header.
        """
        logging.debug('Sending challenge request')
        parsed_url = urlparse.urlparse(response.request.url)
        parsed_auth_url = urlparse.ParseResult(parsed_url.scheme,
                                               parsed_url.netloc,
                                               '/_auth',
                                               parsed_url.params,
                                               parsed_url.query,
                                               parsed_url.fragment)
        response.request.method = 'HEAD'
        response.request.headers['X-CHAP'] = 'request:%s' % self.username
        response.request.url = parsed_auth_url.geturl()
        response.close()
        challenge_response = response.connection.send(response.request,
                                                      **kwargs)
        challenge_response.history.append(response)
        return challenge_response

    def _challenge_response(self, response, **kwargs):
        """Extracts a CHAP challenge from response headers and forms a response.

        Args:
            response: An instance of requests.Response() with the
                'X-CHAP:challenge' header.
            **kwargs: Keyword arguments to pass with subsequent requests.

        Returns:
            An instance of requests.Response() with the appropriate
                'X-CHAP:token' header.

        Raises:
            HttpCrtAuthError: When the X-CHAP:challenge header is missing.
        """
        if response.status_code / 400 == 1:
            raise HttpCrtAuthError(
                ('%s response in challenge reply. '
                    '(Is the server aware of your username or key?)') %
                response.status_code)
        if 'X-CHAP' not in response.headers:
            raise HttpCrtAuthError('Missing CHAP headers in challenge reply.')

        chap_type, chap_challenge = self._parse_chap_header(response.headers)
        if chap_type != 'challenge':
            raise HttpCrtAuthError('Missing CHAP challenge in challenge reply.')

        logging.debug('Sending response to challenge %s', chap_challenge)
        server_netloc = urlparse.urlparse(response.request.url).netloc
        server_name = server_netloc.split(':')[0]
        challenge_response = crtauth_server.create_response(chap_challenge,
                                                            server_name,
                                                            self.signer)
        response.request.method = 'HEAD'
        response.request.headers['X-CHAP'] = 'response:%s' % challenge_response
        response.close()
        token_reply = response.connection.send(response.request, **kwargs)
        token_reply.history.append(response)
        return token_reply

    def _store_chap_token(self, response):
        """Extracts a CHAP token from response headers and stores it.

        Args:
            response: An instance of requests.Response() with the
                'X-CHAP:token:sometoken' header.

        Raises:
            HttpCrtAuthError: When the X-CHAP:token header is missing.
        """
        if 'X-CHAP' not in response.headers:
            raise HttpCrtAuthError('Missing CHAP headers in token reply.')

        chap_type, chap_token = self._parse_chap_header(response.headers)
        if chap_type != 'token':
            raise HttpCrtAuthError('Missing CHAP token in token reply.')

        logging.debug('Stored CHAP token %s', chap_token)
        self.chap_token = chap_token

    def _retry_original(self, response, **kwargs):
        """Resend the original request using our stored CHAP token.

        Args:
            response: An instance of requests.Response()
            **kwargs: Keyword arguments to pass with subsequent requests.

        Returns:
            The requests.Response() to the original request, now with CHAP
                authentication.
        """
        if not self.chap_token:
            raise HttpCrtAuthError('No CHAP token stored.')
        logging.debug('Using newly stored CHAP token.')
        response.request.headers['Authorization'] = 'chap:%s' % self.chap_token
        response.close()
        authd_response = response.connection.send(response.request, **kwargs)
        authd_response.history.append(response)
        return authd_response

    def try_crtauth(self, response, **kwargs):
        """Attempts to authenticate with crtauth, where necessary.

        If the reponse passed in was a 401, attempt to perform CHAP
        authentication using an SSH private key to sign challenges. Otherwise,
        simply return the response unaltered.

        Args:
            response: An instance of requests.Response()
            **kwargs: Keyword arguments to pass with subsequent requests.

        Returns:
            An instance of requests.Response()
        """
        if response.status_code == 401:
            original_request = copy_request(response.request)
            challenge_response = self._challenge_request(response, **kwargs)
            token_reply = self._challenge_response(challenge_response, **kwargs)
            self._store_chap_token(token_reply)
            token_reply.request = original_request
            response = self._retry_original(token_reply, **kwargs)
        return response

    def __call__(self, request):
        # Try to use an existing CHAP token.
        if self.chap_token:
            logging.debug('Using stored CHAP token %s', self.chap_token)
            request.headers['Authorization'] = 'chap:%s' % self.chap_token

        # Fall through to trying to generate a new CHAP token.
        request.register_hook('response', self.try_crtauth)
        return request


def copy_request(request):
    """Copies a PreparedRequest.

    Args:
        request: An instance of requests.PreparedRequest()

    Returns:
        A naive copy of request.
    """
    new_request = requests.PreparedRequest()

    new_request.method = request.method
    new_request.url = request.url
    new_request.body = request.body
    new_request.hooks = request.hooks
    new_request.headers = request.headers.copy()

    return new_request
