import logging
from typing import Dict
import json
from bs4 import BeautifulSoup
from yarl import URL
import time
import re
import requests

from .constants import *


class UnauthorizedError(Exception):
    pass


class SessionError(Exception):
    pass


class VWSession:

    def __init__(self, email, password):
        """
        Initialize a session with the VW API. Requires username and password of the VW ID.
        :param email: VW ID email address (user name)
        :param password: VW ID Password
        """
        self.session = requests.Session()
        self.email = email
        self.password = password
        self.global_config = None
        self.token_timestamp = 0
        self.tokens = {}
        self.logged_in = False
        self.header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0'}


    def clear(self):
        """
        Clears the current sessions cookies
        :return: None
        """
        if self.session is None:
            raise SessionError("No active session")

        if self.session is not None:
            self.session.cookies.clear()

    def log_out(self):
        if self.session is None:
            raise SessionError("No active session")
        if not self.logged_in:
            raise SessionError("Not logged in")

        csrf = self.session.cookies.get("csrf_token")
        r = self.session.get(f"{LOGOUT_URL}?_csrf={csrf}", timeout=HTTP_TIMEOUT, headers=self.header)
        r.close()
        self.logged_in = False

    def log_in(self):
        """
        Log in using the VW ID. Raises an exception on error
        :return: None
        """
        if self.logged_in:
            try:
                self.log_out()
            except Exception as e:
                # Don't let an unsuccessful logout block our login attempt
                logging.warning(f"Couldn't log-out during log-in: {repr(e)}")
                self.logged_in = False

        # Clear client session
        if self.session is not None:
            self.session.close()
            self.session = None

        self.session = requests.Session()
        
        # Start VW Session
        with self.session.get(LOGIN_URL, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            if r.status_code != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status_code}")

            soup = BeautifulSoup(r.text, 'html.parser')

        csrf = soup.find(id="csrf").attrs.get("value")
        relay_state = soup.find(id="input_relayState").attrs.get("value")
        hmac = soup.find(id="hmac").attrs.get("value")
        next_url = soup.find(id="emailPasswordForm").attrs.get("action")

        # Enter email
        params = {"_csrf": csrf, "relayState": relay_state, "hmac": hmac, "email": self.email}
        with self.session.post(VW_IDENTITY_HOST + next_url, params=params, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            if r.status_code != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status_code}")
            soup = BeautifulSoup(r.text, 'html.parser')

        script_field = soup.select_one('script:-soup-contains("templateModel:")').string

        templateModel = json.loads(re.search(r"templateModel\s*:\s*({.*})\s*,\s*\n",script_field).group(1))
        hmac = templateModel["hmac"]
        relay_state = templateModel["relayState"]
        csrf = re.search(r"csrf_token\s*:\s*[\"\'](.*)[\"\']\s*,?\s*\n", script_field).group(1)
        next_url = f"/signin-service/v1/{templateModel['clientLegalEntityModel']['clientId']}/{templateModel['postAction']}"

        # Enter password
        params = {"_csrf": csrf, "relayState": relay_state, "hmac": hmac, "email": self.email, "password": self.password}

        with self.session.post(VW_IDENTITY_HOST + next_url, params=params, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            if r.status_code != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status_code}")

        # get global config
        with self.session.get(VW_GLOBAL_CONFIG_URL, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            self.global_config = json.loads(r.text)

        self.logged_in = True

    def _get_tokens(self):
        """
        Gets the bearer tokens and stores them internally. Should not be called directly. Call check_tokens() instead
        :return: None
        """
        # Refresh session by loading the lounge
        r = self.session.get(LOUNGE_URL, timeout=HTTP_TIMEOUT, headers=self.header)
        r.close()

        # Get Bearer Token
        
        csrf = self.session.cookies.get('csrf_token')
        headers = {"X-CSRF-TOKEN": csrf}
        with self.session.get(TOKEN_URL, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as r:
            if r.status_code != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status_code}")
            self.token_timestamp = time.time()
            self.tokens = json.loads(r.text)

    def check_session(self):
        """
        Checks the validity of the stored tokens and gets new tokens if necessary
        :return: None
        """
        if self.session is None:
            raise SessionError("No active session")
        if not self.logged_in:
            raise SessionError("Not logged in")

        if time.time() - self.token_timestamp > TOKEN_VALIDITY_S:
            self._get_tokens()

    def get_cars(self) -> Dict:
        """
        Get information about the cars from the API. Queries the "relations" and "lounge" APIs
        :return: Dict {"relations": <output of relations API>, "lounge": <output of the lounge API>}
        """
        self.check_session()
        # Get lounge data
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token")}
        with self.session.get(LOUNGE_CARS_URL, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as lounge_request:
            if lounge_request.status_code != 200:
                raise UnauthorizedError(f"Unexpected return code from lounge API:  {lounge_request.status_code}")
            lounge_request_text = lounge_request.text

        # Get relations data
        headers["traceId"] = "1915c3f8-614d-4c4b-a6ac-a05fc52608a8"
        with self.session.get(RELATIONS_URL_V2, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as relations_request:
            if relations_request.status_code != 200:

                raise UnauthorizedError(f"Unexpected return code from Relations API: {relations_request.status_code}")
            relations_request_text = relations_request.text

        return {
            "lounge": json.loads(lounge_request_text),
            "relations": json.loads(relations_request_text).get("relations")
        }

    def get_comm_id_by_comm_nr(self, comm_nr: str) -> str:
        """
        Get the Commissioning ID from a Commissioning Number
        :param comm_nr: Commissioning number e.g. ABC123
        :return: Commissioning ID e.g. ABC123-184.2021
        """
        try:
            valid_bids = self.global_config["spaAsyncConfig"]["serviceConfigs"]["myvw_group-vehicle-file"]["customConfig"]["validBids"]
        except KeyError:
            raise ValueError("Couldn't load list of valid BIDs")

        self.check_session()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token")}
        for year in BID_SEARCH_YEARS:
            for bid in valid_bids:
                with self.session.get(VEHICLE_DATA_PATH + bid + str(year) + comm_nr, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as r:
                    if r.status_code == 200:
                        return f"{comm_nr}-{bid}-{year}"
        raise ValueError("Couldn't find CommID")

    def add_relation_by_comm_id(self, comm_id: str):
        """
        Add a vehicle to the current VW ID by commissioning ID. Raises an exception on error.
        :param comm_id: Commissioning ID e.g. ABC123-184-2021
        :return: None
        """
        self.check_session()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token"),
                   "traceId": "1915c3f8-614d-4c4b-a6ac-a05fc52608a8",
                   "Content-Type": "application/json"}
        payload = {"vehicleNickname": comm_id, "vehicle": {"commissionId": comm_id}}

        with self.session.post(RELATIONS_URL_V1, data=json.dumps(payload), headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as add_request:
            if add_request.status != 201:
                raise UnauthorizedError(f"Couldn't add car ({add_request.status_code}): {add_request.text}")

    def remove_relation_by_comm_id(self, comm_id: str):
        """
        Remove a vehicle from the current VW ID by commissioning ID. Raises an exception on error.
        :param comm_id: Commissioning ID e.g. ABC123-184-2021
        :return: None
        """
        self.check_session()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token"),
                   "traceId": "1915c3f8-614d-4c4b-a6ac-a05fc52608a8",
                   "Content-Type": "application/json"}

        with self.session.delete(f"{MY_VEHICLES_URL}?commissionId={comm_id}", headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as rem_request:
            if not rem_request.ok:
                raise ValueError(f"API returned ({rem_request.status_code}): {rem_request.text}")
