# get_workspace_users.py
#
# Input: None
#
# Output:
#   Full name
#   Primary email
#   Email aliases
#   Organizational unit
#   Suspended status
#   Last login
#
# Export: Timestamped CSV beside this script
#
# Read-only: Does not modify Google Workspace users.

import csv
from datetime import datetime
from pathlib import Path

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


####################################################################################
# SETTINGS
####################################################################################

SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]

SCRIPT_FOLDER = Path(__file__).resolve().parent
CREDENTIALS_FILE = SCRIPT_FOLDER / "credentials.json"
TOKEN_FILE = SCRIPT_FOLDER / "token.json"


####################################################################################
# GOOGLE WORKSPACE CONNECTION
####################################################################################

def connect_google():
    credentials = None

    # Reuse the authorization saved by a previous run.
    if TOKEN_FILE.exists():
        credentials = Credentials.from_authorized_user_file(
            str(TOKEN_FILE), SCOPES
        )

    # Refresh an expired access token when possible.
    if credentials and credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
        except RefreshError:
            credentials = None

    # Open the browser if a new sign-in is required.
    if not credentials or not credentials.valid:
        if not CREDENTIALS_FILE.exists():
            raise FileNotFoundError(
                f"Place your downloaded credentials.json here: {SCRIPT_FOLDER}"
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            str(CREDENTIALS_FILE), SCOPES
        )
        credentials = flow.run_local_server(port=0, prompt="select_account")

    # Save authorization for future runs.
    TOKEN_FILE.write_text(credentials.to_json(), encoding="utf-8")

    return build("admin", "directory_v1", credentials=credentials)


####################################################################################
# RETRIEVE ALL USERS
####################################################################################

def get_users(service):
    results = []
    page_token = None

    while True:
        response = service.users().list(
            customer="my_customer",
            maxResults=500,
            orderBy="email",
            viewType="admin_view",
            pageToken=page_token,
            fields=(
                "nextPageToken,"
                "users(name,primaryEmail,aliases,nonEditableAliases,"
                "orgUnitPath,suspended,lastLoginTime)"
            ),
        ).execute()

        for user in response.get("users", []):
            # Include regular aliases and domain-alias addresses.
            aliases = sorted(set(
                user.get("aliases", [])
                + user.get("nonEditableAliases", [])
            ))

            results.append({
                "FullName": user.get("name", {}).get("fullName", ""),
                "PrimaryEmail": user.get("primaryEmail", ""),
                "Aliases": "; ".join(aliases),
                "OrganizationalUnit": user.get("orgUnitPath", ""),
                "Suspended": user.get("suspended", False),
                "LastLogin": user.get("lastLoginTime") or "Not available",
            })

        print(f"Retrieved {len(results)} users...")

        # Google returns this token when another page is available.
        page_token = response.get("nextPageToken")

        if not page_token:
            break

    return results


####################################################################################
# CONSOLE OUTPUT
####################################################################################

def show_users(results):
    print(f"\nTotal users found: {len(results)}")

    # Print one user at a time so long aliases remain easy to read.
    for user in results:
        print("\n" + "-" * 70)
        print(f"Name:            {user['FullName']}")
        print(f"Primary email:   {user['PrimaryEmail']}")
        print(f"Aliases:         {user['Aliases'] or '(none)'}")
        print(f"Org unit:        {user['OrganizationalUnit']}")
        print(f"Suspended:       {user['Suspended']}")
        print(f"Last login:      {user['LastLogin']}")


####################################################################################
# CREATE CSV
####################################################################################

def export_csv(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = SCRIPT_FOLDER / f"WorkspaceUsers_{timestamp}.csv"

    with csv_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=list(results[0].keys()),
        )
        writer.writeheader()
        writer.writerows(results)

    print(f"\nCSV saved: {csv_path}")


####################################################################################
# RUN SCRIPT
####################################################################################

def main():
    try:
        print("Connecting to Google Workspace...")
        service = connect_google()

        print("Retrieving users...")
        results = get_users(service)

        if not results:
            print("\nNo users found.")
            return

        show_users(results)
        export_csv(results)

    except HttpError as error:
        print(f"\nGoogle API error:\n{error}")

    except (OSError, ValueError, RefreshError) as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()