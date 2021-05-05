#!/usr/bin/env python3
import datetime
import json
import os
import pickle
import re
import sys

import requests
from bs4 import BeautifulSoup

# Login credentials
AZURE_DEVOPS_USERNAME = os.environ["AZURE_DEVOPS_USERNAME"]
AZURE_DEVOPS_PASSWORD = os.environ["AZURE_DEVOPS_PASSWORD"]
# https://dev.azure.com/<project>/
AZURE_DEVOPS_PROJECT = os.environ["AZURE_DEVOPS_PROJECT"]
# Display name of PAT to create
# Default: ScriptGeneratedPAT
AZURE_DEVOPS_PAT_NAME = os.environ.get("AZURE_DEVOPS_PAT_NAME", "ScriptGeneratedPAT")
# Scopes to grant the PAT (separated by spaces, e.g. "vso.work vso.code_write vso.build")
# Default: vso.packaging_write
AZURE_DEVOPS_PAT_SCOPES = os.environ.get("AZURE_DEVOPS_PAT_SCOPES", "vso.packaging_write")
# Always create new PAT even if one already exists with the same name
AZURE_DEVOPS_PAT_ALWAYS_CREATE = os.environ.get("AZURE_DEVOPS_PAT_ALWAYS_CREATE")

# API version
AZURE_DEVOPS_API_VERSION = "5.0-preview.1"

tokens_url = f"https://dev.azure.com/{AZURE_DEVOPS_PROJECT}/_usersSettings/tokens"

try:
    with open(".session_cookies", "rb") as f:
        cookies = pickle.load(f)
        print("Loading previous session cookies")
except (IOError, OSError, pickle.UnpicklingError):
    cookies = None

s = requests.Session()
if cookies:
    s.cookies = cookies

# GET <URL behind authentication>
# -> GET /_signin if unauthenticated
r = s.get(
    url=tokens_url,
    allow_redirects=True,
)
if r.url != tokens_url:
    print("Starting authentication flow")

    soup = BeautifulSoup(r.text, "html.parser")
    options_script = soup.find("script", {"class": "options"})
    options = json.loads(options_script.string)
    auth_url = options["providerOptions"]["orgIdAuthUrl"]

    # GET /authorize
    r = s.get(
        url=auth_url,
    )

    soup = BeautifulSoup(r.text, "html.parser")
    config_script = soup.select_one('script:-soup-contains("$Config")')
    config_script_string = config_script.string.replace("\n", "")
    config_json = re.match(".*\$Config=(.*);", config_script_string).group(1)
    config = json.loads(config_json)

    # Submit username only first
    # POST /GetCredentialType
    r = s.post(
        url=config["urlGetCredentialType"],
        json={
            "isAccessPassSupported": True,
            "flowToken": config["sFT"],
            "isSignup": False,
            "federationFlags": 0,
            "isRemoteConnectSupported": False,
            "isExternalFederationDisallowed": False,
            "forceotclogin": False,
            "country": "GB",
            "originalRequest": config["sCtx"],
            "isFidoSupported": True,
            "isCookieBannerShown": False,
            "isRemoteNGCSupported": True,
            "checkPhones": False,
            "isOtherIdpSupported": True,
            "username": AZURE_DEVOPS_USERNAME,
        },
    )

    credential_type = json.loads(r.text)
    if credential_type["Credentials"]["PrefCredential"] == 1:  # Standard AD login
        print("Starting standard AD login flow")

        # Submit username and password
        # POST /login
        r = s.post(
            url=f"https://login.microsoftonline.com{config['urlPost']}",
            data={
                "i13": "0",
                "login": AZURE_DEVOPS_USERNAME,
                "loginfmt": AZURE_DEVOPS_USERNAME,
                "type": "11",
                "LoginOptions": "3",
                "lrt": "",
                "lrtPartition": "",
                "hisRegion": "",
                "hisScaleUnit": "",
                "passwd": AZURE_DEVOPS_PASSWORD,
                "ps": "2",
                "psRNGCDefaultType": "",
                "psRNGCEntropy": "",
                "psRNGCSLK": "",
                "canary": config["canary"],
                "ctx": config["sCtx"],
                "hpgrequestid": config["sessionId"],
                "flowToken": config["sFT"],
                "PPSX": "",
                "NewUser": "1",
                "FoundMSAs": "",
                "fspost": "0",
                "i21": "0",
                "CookieDisclosure": "0",
                "IsFidoSupported": "0",
                "isSignupPost": "0",
                "i2": "1",
                "i17": "",
                "i18": "",
                "i19": "255857",
            },
        )
        soup = BeautifulSoup(r.text, "html.parser")
        kmsi_config_script = soup.select_one('script:-soup-contains("$Config")')
        kmsi_config_script_string = kmsi_config_script.string.replace("\n", "")
        kmsi_config_json = re.match(".*\$Config=(.*);", kmsi_config_script_string).group(1)
        kmsi_config = json.loads(kmsi_config_json)

        if kmsi_config["urlPost"] != "/kmsi":
            raise Exception(
                f"Unexpected error: urlPost should be /kmsi, not {kmsi_config['urlPost']}. "
                "Please double check your username and password are set correctly: "
                "`echo $AZURE_DEVOPS_USERNAME:$AZURE_DEVOPS_PASSWORD`"
            )

        # "Stay signed in?" confirmation (answer no)
        # POST /kmsi
        r = s.post(
            url=f"https://login.microsoftonline.com{kmsi_config['urlPost']}",
            data={
                "LoginOptions": "3",
                "type": "28",
                "ctx": kmsi_config["sCtx"],
                "hpgrequestid": kmsi_config["sessionId"],
                "flowToken": kmsi_config["sFT"],
                "canary": kmsi_config["canary"],
                "i2": "",
                "i17": "",
                "i18": "",
                "i19": "1873536",
            }
        )
        soup = BeautifulSoup(r.text, "html.parser")
    elif credential_type["Credentials"]["PrefCredential"] == 4:  # Federation redirect
        print("Starting SSO login flow")

        sso_url = credential_type["Credentials"]["FederationRedirectUrl"]

        # GET <ADFS server>/adfs/ls/?client-request-id=&wa=&wtrealm=&wctx=&cbcxt=&username=&mkt=&lc=
        r = s.get(
            url=sso_url,
        )
        soup = BeautifulSoup(r.text, "html.parser")
        login_form = soup.find("form", {"id": "loginForm"})
        login_url = login_form.attrs["action"]
        if not login_url.startswith("http"):
            # Prepend scheme and hostname
            login_url = "/".join(sso_url.split("/")[0:3]) + login_url

        # Username and password submitted
        # POST <ADFS server>/adfs/ls/?client-request-id=&wa=&wtrealm=&wctx=&cbcxt=&username=&mkt=&lc=
        r = s.post(
            url=login_url,
            data={
                "UserName": AZURE_DEVOPS_USERNAME,
                "Password": AZURE_DEVOPS_PASSWORD,
                "AuthMethod": "FormsAuthentication",
            },
            allow_redirects=True,
        )
        soup = BeautifulSoup(r.text, "html.parser")
        login_loading_form = soup.find("form")
        login_loading_url = login_loading_form.attrs["action"]
        login_loading_fields = {
            form_input.attrs["name"]: form_input.attrs["value"]
            for form_input in login_loading_form.find_all("input")
            if "name" in form_input.attrs
        }

        # POST https://login.microsoftonline.com:443/login.srf
        # Form fields at time of writing:
        # - wa
        # - wresult
        # - wctx
        # Redirects to MFA page (https://device.login.microsoftonline.com/) if enabled
        r = s.post(
            url=login_loading_url,
            data=login_loading_fields,
            allow_redirects=True,
        )
        soup = BeautifulSoup(r.text, "html.parser")
        if r.url.startswith("https://device.login.microsoftonline.com"):
            init_mfa_form = soup.find("form")
            init_mfa_url = init_mfa_form.attrs["action"]
            init_mfa_fields = {
                form_input.attrs["name"]: form_input.attrs["value"]
                for form_input in init_mfa_form.find_all("input")
                if "name" in form_input.attrs
            }

            # POST https://login.microsoftonline.com/common/DeviceAuthTls/reprocess
            # Form fields at time of writing:
            # - ctx
            # - flowtoken
            r = s.post(
                url=init_mfa_url,
                data=init_mfa_fields,
                allow_redirects=True,
            )
            soup = BeautifulSoup(r.text, "html.parser")
            mfa_config_script = soup.select_one('script:-soup-contains("$Config")')
            mfa_config_script_string = mfa_config_script.string.replace("\n", "")
            mfa_config_json = re.match(".*\$Config=(.*);", mfa_config_script_string).group(1)
            mfa_config = json.loads(mfa_config_json)

            # ConvergedSA_Core JS file is downloaded and calls:
            # POST https://login.microsoftonline.com/common/SAS/BeginAuth
            r = s.post(
                url="https://login.microsoftonline.com/common/SAS/BeginAuth",
                json={
                    "flowToken": mfa_config["sFT"],
                    "ctx": mfa_config["sCtx"],
                    "Method": "BeginAuth",
                    "AuthMethodId": "OneWaySMS",
                },
            )
            r_json = r.json()
            if not r_json["Success"]:
                raise Exception("MFA code request failed")
            mfa_flow_token = r_json["FlowToken"]
            mfa_ctx = r_json["Ctx"]

            # Ask user to input code
            verification_code = input("Verification code: ")

            # JS calls:
            # POST https://login.microsoftonline.com/common/SAS/EndAuth
            r = s.post(
                url="https://login.microsoftonline.com/common/SAS/EndAuth",
                json={
                    "Method": "EndAuth",
                    "SessionId": mfa_config["sessionId"],
                    "FlowToken": mfa_flow_token,
                    "Ctx": mfa_ctx,
                    "AuthMethodId": "OneWaySMS",
                    "AdditionalAuthData": verification_code,
                    "PollCount": 1,
                },
            )
            r_json = r.json()
            if not r_json["Success"]:
                raise Exception("MFA code verification failed")
            mfa_flow_token = r_json["FlowToken"]
            mfa_ctx = r_json["Ctx"]

            # JS calls:
            # POST https://login.microsoftonline.com/common/SAS/ProcessAuth
            # Form redirects to /_signedin
            r = s.post(
                url="https://login.microsoftonline.com/common/SAS/ProcessAuth",
                data={
                    "type": "18",
                    "GeneralVerify": "false",
                    "request": mfa_ctx,
                    # Optional:
                    # "mfaLastPollStart": "1620245010877",
                    # "mfaLastPollEnd": "1620245011166",
                    "mfaAuthMethod": "OneWaySMS",
                    "canary": config["canary"],
                    "otc": verification_code,
                    "login": AZURE_DEVOPS_USERNAME,
                    "flowToken": mfa_flow_token,
                    "hpgrequestid": config["sessionId"],
                    "sacxt": "",
                    "hideSmsInMfaProofs": "false",
                    "i2": "",
                    "i17": "",
                    "i18": "",
                    "i19": "10087",
                },
            )
            soup = BeautifulSoup(r.text, "html.parser")
            process_auth_form = soup.find("form")
            process_auth_url = process_auth_form.attrs["action"]
            process_auth_fields = {
                form_input.attrs["name"]: form_input.attrs["value"]
                for form_input in process_auth_form.find_all("input")
                if "name" in form_input.attrs
            }

    # POST https://spsprodweu3.vssps.visualstudio.com/_signedin
    # Form fields at time of writing:
    # - code
    # - id_token
    # - state
    # - session_state
    sign_in_form = soup.find("form")
    sign_in_url = sign_in_form.attrs["action"]
    sign_in_fields = {
        form_input.attrs["name"]: form_input.attrs["value"]
        for form_input in sign_in_form.find_all("input")
        if "name" in form_input.attrs
    }

    r = s.post(
        url=sign_in_url,
        data=sign_in_fields,
    )
    soup = BeautifulSoup(r.text, "html.parser")

    # POST https://vssps.dev.azure.com/serviceHosts/<uuid>/_signedin?realm=dev.azure.com&protocol=&reply_to=<app_url>
    # Form fields at time of writing:
    # - id_token
    # - FedAuth
    # - FedAuth1
    finish_sign_in_form = soup.find("form")
    finish_sign_in_url = finish_sign_in_form.attrs["action"]
    finish_sign_in_fields = {
        form_input.attrs["name"]: form_input.attrs["value"]
        for form_input in finish_sign_in_form.find_all("input")
        if "name" in form_input.attrs
    }

    r = s.post(
        url=finish_sign_in_url,
        data=finish_sign_in_fields,
    )
    if r.status_code != 200:
        raise Exception("Login failed")

    with open(".session_cookies", "wb") as f:
        pickle.dump(s.cookies, f)

################################################################
# Login finished
################################################################

if not AZURE_DEVOPS_PAT_ALWAYS_CREATE:
    # Get PAT list and check if the script PAT already exists
    r = s.get(
        url=f"https://vssps.dev.azure.com/{AZURE_DEVOPS_PROJECT}/_apis/Token/SessionTokens?api-version={AZURE_DEVOPS_API_VERSION}",
    )
    r_json = r.json()
    existing_token_names = set(token["displayName"] for token in r_json["value"])
    if AZURE_DEVOPS_PAT_NAME in existing_token_names:
        y_or_n = input(f"PAT with name {AZURE_DEVOPS_PAT_NAME} already exists. Create new one anyway? (y/N) ")
        if y_or_n.lower() != "y":
            print("Exiting...")
            sys.exit(1)

# Get project ID
r = s.get(url=tokens_url)
soup = BeautifulSoup(r.text, "html.parser")
data_providers_script = soup.find("script", {"id": "dataProviders"})
data_providers_json = json.loads(data_providers_script.string)
project_id = data_providers_json["data"]["ms.vss-web.page-data"]["hostId"]

# Create PAT with validity of 2 years
valid_to = datetime.datetime.now() + datetime.timedelta(days=365*2)
r = s.post(
    url=f"https://dev.azure.com/{AZURE_DEVOPS_PROJECT}/_apis/Contribution/HierarchyQuery?api-version={AZURE_DEVOPS_API_VERSION}",
    json={
        "dataProviderContext": {
            "properties": {
                # Optional:
                # "sourcePage": {
                #     "routeValues": {
                #         "serviceHost": "<app uuid> (<app name>)",
                #         "action": "Execute",
                #         "controller": "ContributedPage",
                #         "adminPivot": "tokens"
                #     },
                #     "routeId": "ms.vss-admin-web.user-admin-hub-route",
                #     "url": "https://dev.azure.com/<app name>/_usersSettings/tokens"
                # },
                "targetAccounts": [project_id],
                "scope": AZURE_DEVOPS_PAT_SCOPES,
                "validTo": valid_to.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "displayName": AZURE_DEVOPS_PAT_NAME,
            },
        },
        "contributionIds": [
            "ms.vss-token-web.personal-access-token-issue-session-token-provider",
        ],
    }
)
if r.status_code != 200:
    raise Exception("PAT creation failed")

# Output newly created PAT
print("Created new PAT:")
print(r.json()["dataProviders"]["ms.vss-token-web.personal-access-token-issue-session-token-provider"]["token"])
