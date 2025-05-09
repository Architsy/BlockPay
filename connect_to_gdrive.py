from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import os

# Define the scope for Google Drive access
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def authenticate_google_drive():
    """Authenticate user and return Google Drive service."""
    creds = None
    token_path = "token.json"

    # Check if token.json exists (to avoid re-authentication)
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    # Authenticate if credentials are missing or expired
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for future use
        with open(token_path, "w") as token_file:
            token_file.write(creds.to_json())

    # Return the authenticated Google Drive service
    return build("drive", "v3", credentials=creds)

def create_drive_folder(service, folder_name):
    """Creates a folder in Google Drive and returns its folder ID."""
    query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    response = service.files().list(q=query, spaces="drive", fields="files(id)").execute()
    
    if response["files"]:
        print(f"Folder '{folder_name}' already exists.")
        return response["files"][0]["id"]  # Return existing folder ID
    
    folder_metadata = {
        "name": folder_name,
        "mimeType": "application/vnd.google-apps.folder"
    }
    folder = service.files().create(body=folder_metadata, fields="id").execute()
    print(f"Folder '{folder_name}' created successfully!")
    return folder.get("id")

def upload_to_drive(file_path, folder_name):
    """Uploads a binary file to a specific Google Drive folder."""
    drive_service = authenticate_google_drive()

    # Create folder if it doesn't exist
    folder_id = create_drive_folder(drive_service, folder_name)

    # File metadata
    file_metadata = {
        "name": os.path.basename(file_path),
        "parents": [folder_id]  # Upload inside the specified folder
    }

    # Upload file as a binary stream
    media = MediaFileUpload(file_path, mimetype="application/octet-stream", resumable=True)
    file = drive_service.files().create(body=file_metadata, media_body=media, fields="id").execute()

    print(f"File '{file_path}' uploaded successfully! File ID: {file.get('id')}")

if __name__ == "__main__":
    upload_to_drive("solana/real stuff/testfile.txt", "SecureKeys")  # Replace with your file & folder name
