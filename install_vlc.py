import requests
import hashlib
import subprocess
import os

def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """
    Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer

    """
    # TODO: Step 1
    expected_sha_url = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe.sha256'
    expected_sha = requests.get(expected_sha_url)

    if expected_sha.status_code == requests.codes.ok:

        file_content = expected_sha.text
        sha_value = file_content.split()[0].lower()

        return sha_value
    
    else: 
        None

def download_installer():
    """
    Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data

    """
    # TODO: Step 2
    vlc_installer = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe'
    vlc_exe = requests.get(vlc_installer)

    if vlc_exe.status_code == requests.codes.ok:

        file_c = vlc_exe.content

    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    return file_c

def installer_ok(installer_data, expected_sha256):
    """
    Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.

    """    
    # TODO: Step 3

    data_hash = hashlib.sha256(installer_data).hexdigest().lower()    

    return data_hash == expected_sha256

    # Hint: See example code in lab instructions entitled "Computing the Hash Value of a Response Message Body"


def save_installer(installer_data):
    """
    Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file

    """
    # TODO: Step 4

    inst_path = r'C:\Lab 6 Folder Uses\vlc_installer.exe'

    with open (inst_path, 'wb') as file:
        file.write(installer_data)

    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    
    return inst_path

def run_installer(installer_path):
    """
    Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file

    """    
    # TODO: Step 5

    subprocess.run([installer_path, '/S'])
    
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    return
    
def delete_installer(installer_path):
    # TODO: Step 6

    os.remove(installer_path)

    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """
    Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file

    """
    return

if __name__ == '__main__':
    main()