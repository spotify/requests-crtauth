# -*- coding: utf-8 -*-
"""HTTP crtauth authentication using the requests library."""

import logging
import os
import urlparse

from crtauth import ssh as crtauth_ssh
from crtauth import client as crtauth_client
import requests


class HttpCrtAuthError(requests.exceptions.RequestException):
    """Raised when Crt Authentication fails."""


class HttpCrtAuth(requests.auth.AuthBase):
    def __init__(self, username=None, private_key=None, signer=None, version=1):
        """HTTP crtauth authentication using the requests library.

        Args:
            username: User to authenticate as. Defaults to $USER.
            private_key: A PEM encoded private key string. Overrides signer.
            signer: A crtauth SigningPlug instance. Defaults to using the
                SSH agent (AgentSigner).
            version: Integer version of the crtauth protocol.
        """
        self.username = username or os.environ.get('USER')
        if private_key:
            self.signer = crtauth_ssh.SingleKeySigner(private_key)
        else:
            self.signer = signer
        self.chap_token = None
        self.version = version

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
        request = _consume_response(response)
        if self.version == 0:
            challenge = self.username
        else:
            challenge = crtauth_client.create_request(self.username)
        request.headers['X-CHAP'] = 'request:%s' % challenge
        request.url = _auth_url(request.url)
        # HEAD is no longer required as of crtauth 0.99.3, but it shouldn't
        # hurt for compatibility with older versions.
        request.method = 'HEAD'
        challenge_response = response.connection.send(request, **kwargs)
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

        chap_type, chap_challenge = _parse_chap_header(response.headers)
        if chap_type != 'challenge':
            raise HttpCrtAuthError('Missing CHAP challenge in challenge reply.')

        logging.debug('Sending response to challenge %s', chap_challenge)
        request = _consume_response(response)
        challenge_response = crtauth_client.create_response(
            chap_challenge,
            _crtauth_server_name(request.url),
            self.signer)
        request.headers['X-CHAP'] = 'response:%s' % challenge_response
        token_reply = response.connection.send(request, **kwargs)
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

        chap_type, chap_token = _parse_chap_header(response.headers)
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
        request = _consume_response(response)
        request.headers['Authorization'] = 'chap:%s' % self.chap_token
        authd_response = response.connection.send(request, **kwargs)
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
            original_request = _consume_response(response)
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


def _crtauth_server_name(url):
    """Returns the server name (FQDN) based on the request URL.

    Args:
        url: String, the original request.url

    Returns:
        String, the server name for crtauth authentication.
    """
    server_netloc = urlparse.urlparse(url).netloc
    return server_netloc.split(':')[0]


def _auth_url(url):
    """Returns the authentication URL based on the URL originally requested.

    Args:
        url: String, the original request.url

    Returns:
        String, the authentication URL.
    """
    parsed_url = urlparse.urlparse(url)
    parsed_auth_url = urlparse.ParseResult(parsed_url.scheme,
                                           parsed_url.netloc,
                                           '/_auth',
                                           parsed_url.params,
                                           parsed_url.query,
                                           parsed_url.fragment)
    return parsed_auth_url.geturl()


def _parse_chap_header(headers):
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


def _consume_response(response):
    """Consume content and release the original connection.

    Args:
        response: A requests.Response to whose connection to reuse.

    Returns:
        requests.PreparedRequest, a copy of the response's request.
    """
    response.content
    response.close()
    return response.request.copy()
