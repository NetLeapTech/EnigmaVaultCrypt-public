import configparser
import base64
import os
import re
import pickle
from typing import Any, Optional


def write_config(section: str, title: str, content: Any, file_path: str) -> None:
    if not all([section, title, content, file_path]):
        raise ValueError("All parameters must be provided and non-empty")

    if not re.match(r'^[\w\s]+$', section):
        raise ValueError("Section must be a string containing letters, numbers, underscores, and spaces only")
    if not re.match(r'^[\w\s]+$', title):
        raise ValueError("Title must be a string containing letters, numbers, underscores, and spaces only")

    dir_path = os.path.dirname(file_path)
    if not os.path.isdir(dir_path):
        raise ValueError("The file path must be a valid directory")

    if not os.access(dir_path, os.W_OK):
        raise PermissionError("The directory does not have write permission")

    config = configparser.ConfigParser()
    config.read(file_path)

    if not config.has_section(section):
        config.add_section(section)

    serialized_content = base64.b64encode(pickle.dumps(content)).decode('utf-8')
    config.set(section, title, serialized_content)

    with open(file_path, 'w') as configfile:
        config.write(configfile)


def read_config(section: str, title: str, file_path: str) -> Any:
    if not all([section, title, file_path]):
        raise ValueError("All parameters must be provided and non-empty")

    if not re.match(r'^[\w\s]+$', section):
        raise ValueError("Section must be a string containing letters, numbers, underscores, and spaces only")
    if not re.match(r'^[\w\s]+$', title):
        raise ValueError("Title must be a string containing letters, numbers, underscores, and spaces only")

    if not os.path.isfile(file_path):
        raise ValueError("The file path must be a valid file")

    if not os.access(file_path, os.R_OK):
        raise PermissionError("The file does not have read permission")

    config = configparser.ConfigParser()
    config.read(file_path)

    if not config.has_section(section):
        raise ValueError(f"Section {section} not found in the config file.")

    encoded_content = config.get(section, title, fallback=None)
    if encoded_content is None:
        raise ValueError(f"Title {title} not found in section {section}.")

    content = pickle.loads(base64.b64decode(encoded_content.encode('utf-8')))
    return content


def remove_config_item(section: str, title: Optional[str], file_path: str) -> None:
    if not all([section, file_path]):
        raise ValueError("Section and file path must be provided and non-empty")

    if not re.match(r'^[\w\s]+$', section):
        raise ValueError("Section must be a string containing letters, numbers, underscores, and spaces only")

    if title is not None:
        if not re.match(r'^[\w\s]+$', title):
            raise ValueError("Title must be a string containing letters, numbers, underscores, and spaces only")

    if not os.path.isfile(file_path):
        raise ValueError("The file path must be a valid file")

    if not os.access(file_path, os.W_OK):
        raise PermissionError("The file does not have write permission")

    config = configparser.ConfigParser()
    config.read(file_path)

    if not config.has_section(section):
        raise ValueError(f"Section {section} not found in the config file.")

    if title:
        if not config.remove_option(section, title):
            raise ValueError(f"Title {title} not found in section {section}.")
    else:
        config.remove_section(section)

    with open(file_path, 'w') as configfile:
        config.write(configfile)


def delete_config_file(file_path: str) -> None:
    if not os.path.isfile(file_path):
        raise ValueError("The file path must be a valid file")

    if not os.access(file_path, os.W_OK):
        raise PermissionError("The file does not have delete permission")

    os.remove(file_path)

