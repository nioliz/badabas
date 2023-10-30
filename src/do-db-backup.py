#!/usr/bin/env python3

import argparse
import gzip
import logging

# import logging.handlers
import os
import re
import shutil
import subprocess
import tempfile

from datetime import datetime
from pathlib import PurePath

# For parsing config file
import yaml


# For file sizes
def convert_bytes(num):
    """
    this function will convert bytes to MB.... GB... etc

    Args:
      num: File size in bytes

    Returns:
      string: File size in human-readable format
    """

    res = ""
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            res = "%3.1f %s" % (num, x)
        num /= 1024.0
    return res


def file_size(file_path, best_postfix):
    """
    This function will return the file size as string or "not a file"

    Args:
        file_path (string): Full file name
        best_postfix (boolean): Used human-readable format or not?
    """

    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        if best_postfix:
            return convert_bytes(file_info.st_size)
        else:
            return file_info.st_size
    else:
        return "not a file"


def generate_first_dump_args(source, password_file):
    """

    Args:
        source:

    Returns:
        dump_args -- starting part of backup command
    """
    try:
        # Base arguments to pass to mysqldump
        # FIXME: Support compression
        # FIXME: Support option quick
        # FIXME: Support option lock-tables
        dump_args = ["mysqldump", "--dump-date",  # Add time dump was completed
            "--host={}".format(source["host"]), "--port={}".format(source.get("port", 3306)),  # Defaults to 3306
            "--user={}".format(source["user"]), ]

        # Enable single transaction (No locking of databases) by default
        if source.get("single-transaction", True):
            dump_args.append("--single-transaction")

        if "password" in source:

            # Write password to file
            password_file.write("[mysqldump]\npassword={}".format(source["password"]).encode("utf-8"))

            # Point to beginning of file so mysqldump can read the whole file
            password_file.seek(0)

            # Make mysqldump read the config file
            dump_args.insert(1, "--defaults-file={}".format(password_file.name))
        else:
            # Make it clear that no password is to be used
            # Adding this will warn me of using password on the command line??
            # args.append('--skip-password')
            pass

    except KeyError as ex:
        logging.error("%s: Skipping because of missing key '%s' in source config", b_name, ex)
        return None

    return dump_args, password_file


def dump_mysql_db(dump_args, dbname):
    """

    Args:
        dump_args (basestring[]):
        dbname (_TemporaryFileWrapper[str]):

    Returns:
        _TemporaryFileWrapper[str]:
    """
    # Dump database to the temp file
    try:
        db_raw = tempfile.NamedTemporaryFile()
        r = subprocess.run(dump_args + [dbname], stdout=db_raw, check=True,  # Throw exception on non 0 exit code
            timeout=config["timeout"], )
        logging.debug("%s: %s", b_name, r)

    except subprocess.CalledProcessError as e:
        logging.error("%s: %s", b_name, e)
        return None
    return db_raw


def compress_db_dump(db_raw):
    """

    Returns:
        _TemporaryFileWrapper[str]: compressed dump file
    """
    # Compress database dump
    try:
        db_gzip = tempfile.NamedTemporaryFile()
        with open(db_raw.name, "rb") as f_in:
            with gzip.open(db_gzip.name, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    except Exception as e:
        logging.error("%s: When compressing the database file: %s", b_name, e)
        return None
    finally:
        # Remove temp file
        db_raw.close()

    # Get the size of the compressed temp file to back up
    # b_size = file_size(
    #     db_gzip.name,
    #     config.get("bitmath_bestprefix", True),
    # )
    return db_gzip


def get_local_backup_cmds(b_datetime, ready_file_name, dest):  # dt, db_gzip.name
    path_temp = tempfile.NamedTemporaryFile()
    path_dest = PurePath(dest["path"], config["rootdir"], b_name, str(b_datetime.year), str(b_datetime.month),
        path_temp.name, )

    commands = [# Make the destination dir
        ["mkdir", "-p", path_dest.parent], # Copy the temp file to destination dir
        ["cp", ready_file_name, path_dest], ]
    return commands


def get_s3_backup_cmds(b_datetime, ready_file_name, dest):
    """
    Sending the file to s3
    Args:
        ready_file_name: Name of file to send
        b_datetime (datetime): Execution starting time

    Returns:
        basestring[]: Array of command to execute
    """
    path_temp = tempfile.NamedTemporaryFile()
    path_dest = PurePath("s3:", dest.get("bucket", os.getenv("S3_BUCKET")), config["rootdir"], b_name,
        str(b_datetime.year), str(b_datetime.month), path_temp.name,  # File name temp file
    )

    # rclone base args. Credentials from env if not in config
    rc_args = ["rclone", "--config", config["rclone_config"], "--s3-endpoint",
        dest.get("endpoint", os.getenv("S3_ENDPOINT")), "--s3-access-key-id",
        dest.get("access_key_id", os.getenv("S3_ACCESS_KEY_ID")), "--s3-secret-access-key",
        dest.get("secret_access_key", os.getenv("S3_SECRET_ACCESS_KEY")), ]

    # FIXME: If debug, print out rclone version
    # rc_args + ['version']
    # rc_args + ['ls', s3_path]
    # rc_args + ['size', s3_path]

    # Bild commands to perform
    commands = [# Make the destination dir (It may not exist)
        rc_args + ["mkdir", path_dest.parent], # Copy the file to S3
        rc_args + ["copy", ready_file_name, path_dest], ]
    return commands


def exec_backup_cmd(backup_cmd):
    # Perform backup commands
    try:
        # FIXME: Add dry-run option in config
        for c in backup_cmd:
            # FIXME: Add timeout?
            r = subprocess.run(c, check=True)
            logging.debug("%s: %s", b_name, clean_args(r.args))

    except subprocess.CalledProcessError as e:
        logging.error("%s: %s", b_name, clean_args(e.cmd))
        return False  # FIXME: Delete db dump?
    else:
        logging.info("Executing backup cmd '%s' failed!", backup_cmd)
    finally:
        return True


# FIXME: Make a list if command line arguments which should
# be obfuscated when logging. Don't leak secrets in logs!
SECRET_ARGS = ["--s3-access-key-id", "--s3-secret-access-key", ]

# The exit code to report when script is done
# Errors may have occured, but we want to complete as many backups
# as possible. Hence, we do not exit on errors during backups
EXIT_CODE = 0


def clean_args(args):
    """
    Hide sensitive information in command arguments list
    """

    # If we find a sensitve argument in the list
    # Replace the following entry in the list
    # That must be the secret
    for s in SECRET_ARGS:
        try:
            args[args.index(s) + 1] = "******"
        except:
            pass

    # Return object with no sensitive information
    return args


# Valid types
TYPES = {"source": ["mysql", "postgres"], "destination": ["s3", "local"]}

# Backup names can only have word characters and '-'
re_backup_name = re.compile("^[\w-]+$")

# FLAGS #

parser = argparse.ArgumentParser(description="Database backups. Supply a config file with backups to perform.")

parser.add_argument("--config", required=False, help=("Configuration file"), default="/etc/backups.yaml")

parser.add_argument("--log-file", required=False, help=("Log file"))

# Parse the command line arguments
args = parser.parse_args()

# LOAD CONFIG #

# Load configuration file
try:
    stream = open(args.config, "r")
except FileNotFoundError:
    logging.error(
        "Configuration file '{}' was not found. Use flag '--config FILE' to override default config file path.".format(
            args.config))
    exit(1)

# Parse the config file
try:
    config = yaml.safe_load(stream)
except yaml.YAMLError as e:
    logging.error("Could not parse configuration file: %s", e)
    exit(2)

# LOGGING #

# Log to stdout
logging_handlers = [logging.StreamHandler()]

# Add logging to file if flag is set
if args.log_file:
    logging_handlers.append(logging.FileHandler(args.log_file))

# Configure logging
logging.basicConfig(format="%(asctime)s:%(levelname)s:%(message)s", level=config.get("loglevel", "INFO").upper(),
    handlers=logging_handlers, )


def dumpmysql(b_name, b_conf):
    # Abort on invalid backup name

    # Source config
    s = b_conf["source"]

    # Destination config
    d = b_conf["destination"]

    # A temp file for storing the password to use for database access
    # This way, we can't leak it in the logs, and we get no warning
    # about using passwords on the command line
    password_file = tempfile.NamedTemporaryFile()

    # Iterate over databases of single job (host) to back up them all
    for db in s["databases"]:
        # The official time for this backup
        b_datetime = datetime.now()

        # Store raw database dump here
        db_gzip = compress_db_dump(dump_mysql_db(generate_first_dump_args(s, password_file), db))

        # Send to Remote #

        # Build commands and paths to use
        try:
            # Local backup
            if d["type"] == "local":
                exec_backup_cmd(get_local_backup_cmds(b_datetime, db_gzip.name, b_conf["destination"]))

            # Backup to S3
            elif d["type"] == "s3":
                exec_backup_cmd(get_s3_backup_cmds(b_datetime, db_gzip.name, b_conf["destination"]))

        except KeyError as ex:
            logging.error("%s: Skipping because of missing key %s in destination config", b_name, ex, )
            # FIXME: Delete db dump
            return 126

    password_file.close()
    return 0


def dump_postgres():
    return 0


# Timeout when dumping database
config["timeout"] = config.get("timeout", 600)

# This is dir on the remote where backups will be stored
config["rootdir"] = config.get("rootdir", "database_backups")

# Path to rclone configuration file
config["rclone_config"] = config.get("rclone_config", "/etc/rclone.conf")

# Check rclone config
if not os.path.isfile(config["rclone_config"]):
    raise ValueError("'{}' is not a file".format(config["rclone_config"]))

dumpdbs = {}

dumpdbs['mysql'] = dumpmysql

# Run through the backups to perform
for b_name, b_conf in config["backups"].items():

    if not re_backup_name.match(b_name):
        logging.error("Invalid backup name '%s'", b_name)
        EXIT_CODE = 126
        continue

    # Check source type
    if b_conf["source"]["type"] not in TYPES["source"]:
        logging.error("%s: Unknown source type '%s'", b_name, b_conf["source"]["type"])
        EXIT_CODE = 126
        continue

        # DUMP DATABASE #

    dumpdbs[b_conf["source"]["type"]](b_name, b_conf)
exit(EXIT_CODE)
