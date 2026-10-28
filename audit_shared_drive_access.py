# audit_shared_drive_access.py
#
# Input: None
#
# Output: Timestamped CSV containing:
#   Shared Drive name and ID
#   Member name, email, and type
#   Permission level
#   External access classification
#   Group review notes
#
# Read-only: Does not modify drives or permissions.
# Reports drive-level permissions only.
# Does not expand group membership or scan files/folders.

####################################################################################
# REQUIREMENTS - INSTALL MISSING MODULES
####################################################################################

import importlib.util
import subprocess
import sys

REQUIRED_PACKAGES = {
    "googleapiclient": "google-api-python-client",
    "google.auth": "google-auth",
    "google_auth_httplib2": "google-auth-httplib2",
    "google_auth_oauthlib": "google-auth-oauthlib",
}

for module, package in REQUIRED_PACKAGES.items():
    try:
        installed = importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        installed = False

    if not installed:
        print(f"Installing missing package: {package}")

        subprocess.check_call([
            sys.executable,
            "-m",
            "pip",
            "install",
            package
        ])

####################################################################################
# IMPORT MODULES
####################################################################################
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

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

# Add any other company-owned Google Workspace domains here.
# Addresses outside this list are classified as external.
INTERNAL_DOMAINS = {
    "convergemarketing.com",
    "convergedirect.com",
}

SCRIPT_FOLDER = Path(__file__).resolve().parent
CREDENTIALS_FILE = SCRIPT_FOLDER / "credentials.json"
TOKEN_FILE = SCRIPT_FOLDER / "token_drive.json"

ROLE_NAMES = {
    "organizer": "Manager",
    "fileOrganizer": "Content Manager",
    "writer": "Contributor",
    "commenter": "Commenter",
    "reader": "Viewer",
    "owner": "Owner",
}

CSV_COLUMNS = [
    "DriveName",
    "DriveId",
    "MemberName",
    "Email",
    "MemberType",
    "Domain",
    "PermissionLevel",
    "ApiRole",
    "ExternalAccess",
    "Deleted",
    "Status",
    "Notes",
]


####################################################################################
# GOOGLE DRIVE CONNECTION
####################################################################################

def connect_google():
    credentials = None

    if TOKEN_FILE.exists():
        credentials = Credentials.from_authorized_user_file(
            str(TOKEN_FILE), SCOPES
        )

    if credentials and credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
        except RefreshError:
            credentials = None

    if not credentials or not credentials.valid:
        if not CREDENTIALS_FILE.exists():
            raise FileNotFoundError(
                f"Place credentials.json here: {SCRIPT_FOLDER}"
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            str(CREDENTIALS_FILE), SCOPES
        )
        credentials = flow.run_local_server(
            port=0,
            prompt="select_account",
        )

    TOKEN_FILE.write_text(credentials.to_json(), encoding="utf-8")

    return build("drive", "v3", credentials=credentials)


####################################################################################
# RETRIEVE SHARED DRIVES
####################################################################################

def get_shared_drives(service):
    drives = []
    page_token = None

    while True:
        response = service.drives().list(
            useDomainAdminAccess=True,
            pageSize=100,
            pageToken=page_token,
            fields="nextPageToken,drives(id,name)",
        ).execute(num_retries=3)

        drives.extend(response.get("drives", []))
        page_token = response.get("nextPageToken")

        if not page_token:
            break

    return sorted(drives, key=lambda drive: drive["name"].lower())


####################################################################################
# RETRIEVE DRIVE MEMBERS
####################################################################################

def get_permissions(service, drive_id):
    permissions = []
    page_token = None

    while True:
        response = service.permissions().list(
            fileId=drive_id,
            supportsAllDrives=True,
            useDomainAdminAccess=True,
            pageSize=100,
            pageToken=page_token,
            fields=(
                "nextPageToken,"
                "permissions(id,type,displayName,emailAddress,"
                "domain,role,deleted)"
            ),
        ).execute(num_retries=3)

        permissions.extend(response.get("permissions", []))
        page_token = response.get("nextPageToken")

        if not page_token:
            break

    return permissions


####################################################################################
# CLASSIFY EXTERNAL ACCESS
####################################################################################

def classify_access(permission):
    member_type = permission.get("type", "")
    email = permission.get("emailAddress", "")
    domain = permission.get("domain", "").lower()
    notes = ""

    if member_type in ("user", "group"):
        domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""

        if not domain:
            external = "Unknown"
        elif domain in INTERNAL_DOMAINS:
            external = "No"
        else:
            external = "Yes"

        if member_type == "group":
            notes = (
                "Group members not expanded; classification is based "
                "on the group's email domain."
            )

    elif member_type == "domain":
        if not domain:
            external = "Unknown"
        else:
            external = "No" if domain in INTERNAL_DOMAINS else "Yes"

    elif member_type == "anyone":
        external = "Yes"
        notes = "Anyone access."

    else:
        external = "Unknown"

    return domain, external, notes


####################################################################################
# AUDIT ALL DRIVES
####################################################################################

def audit_drives(service, drives):
    results = []
    failed_drives = 0

    for index, drive in enumerate(drives, start=1):
        print(f"[{index}/{len(drives)}] Checking {drive['name']}...")

        try:
            permissions = get_permissions(service, drive["id"])

        except HttpError as error:
            failed_drives += 1
            print(f"  Unable to read permissions: HTTP {error.resp.status}")

            results.append({
                "DriveName": drive["name"],
                "DriveId": drive["id"],
                "Status": "Error",
                "Notes": str(error),
            })
            continue

        if not permissions:
            results.append({
                "DriveName": drive["name"],
                "DriveId": drive["id"],
                "Status": "No permissions returned",
                "Notes": "No permission entries returned by the API.",
            })
            continue

        for permission in permissions:
            domain, external, notes = classify_access(permission)
            role = permission.get("role", "")

            results.append({
                "DriveName": drive["name"],
                "DriveId": drive["id"],
                "MemberName": permission.get("displayName", ""),
                "Email": permission.get("emailAddress", ""),
                "MemberType": permission.get("type", ""),
                "Domain": domain,
                "PermissionLevel": ROLE_NAMES.get(role, role),
                "ApiRole": role,
                "ExternalAccess": external,
                "Deleted": permission.get("deleted", False),
                "Status": "OK",
                "Notes": notes,
            })

    return results, failed_drives


####################################################################################
# CREATE CSV
####################################################################################

def export_csv(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = SCRIPT_FOLDER / f"SharedDriveAccess_{timestamp}.csv"

    with csv_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nCSV saved: {csv_path}")


####################################################################################
# RUN SCRIPT
####################################################################################

def main():
    try:
        print("Connecting to Google Drive...")
        service = connect_google()

        print("Retrieving organization Shared Drives...")
        drives = get_shared_drives(service)

        if not drives:
            print("\nNo Shared Drives returned.")
            return

        results, failed_drives = audit_drives(service, drives)
        export_csv(results)

        members = [row for row in results if row["Status"] == "OK"]
        external_count = sum(
            row["ExternalAccess"] == "Yes" and not row["Deleted"]
            for row in members
        )
        group_count = sum(
            row["MemberType"] == "group" and not row["Deleted"]
            for row in members
        )

        print(f"Shared Drives found: {len(drives)}")
        print(f"Permission entries reported: {len(members)}")
        print(f"External entries (excluding deleted): {external_count}")
        print(f"Group entries requiring member review: {group_count}")
        print(f"Drives that could not be audited: {failed_drives}")

        if failed_drives:
            print("Report is incomplete. See rows with Status = Error.")

    except HttpError as error:
        print(f"\nGoogle API error:\n{error}")

    except (OSError, ValueError, RefreshError) as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()