#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess

from datetime import datetime
from pathlib import PurePath

import yaml

#import tempfile


parser = argparse.ArgumentParser(description='Database backups')

parser.add_argument(
    '--config',
    required=False,
    help=('Configuration file'),
    default='/etc/backups.yaml'
    )

parser.add_argument(
    '--log-file',
    required=False,
    help=('Log file')
    )

# Parse the command line arguments
args = parser.parse_args()

# A list of logging handlers
logging_handlers = []

# Handler for logging to file
if args.log_file:
  logging_handlers.append(logging.FileHandler(args.log_file))
  
# Always log to stdout
logging_handlers.append(logging.StreamHandler())


# Load configuration file
try:
  stream = open(args.config, 'r')
except FileNotFoundError:
  logging.error("Configuration file '{}' was not found. Use flag '--config FILE' to override default config file path.".format(args.config))
  exit(1)

config = yaml.safe_load(stream)


# Configure logging
logging.basicConfig(
  format='%(asctime)s:%(levelname)s:%(message)s',
  level=eval("logging.{}".format(config.get('loglevel', "INFO").upper())),
  handlers=logging_handlers
  )


# Dir to store local temporary backups
BACKUP_DIR = '/tmp'

try:
  # Default timeout when dumping database
  DUMP_TIMEOUT = config['timeout']

  # This is dir on the remote where backups will be stored
  TOP_DIR = config['rootdir']
  
  config['rclone_config']
except KeyError as e:
  logging.error("Missing key %s in config", e)
  exit(1)



for b_name, b_conf in config['backups'].items():
  logging.debug("%s: Processing backup entry", b_name)
  

  # FIXME: Validate config
  try:
    # Source config
    s = b_conf['source']

    # Destination config
    d = b_conf['destination']

    # The arguments to pass to mysqldump
    args = [
      'mysqldump',
      '--host=' + s['host'],
      # Default port if not defined
      '--port=' + str(s.get('port', 3306)),
      '--user=' + str(s['user']),
      '--password=' + str(s['password']),
      '--databases'
      ]
    # List of databases to back up
    dbs = s['databases']

  except KeyError as e:
    logging.error("%s: Skipping because of missing key '%s' in source config", b_name, e)
    continue

  # Run through databases to back up
  for db in dbs:
    # The official time for this backup
    b_datetime = datetime.now()

    # Full path to the temporary local backup
    path_temp = PurePath(
      BACKUP_DIR,
      "{}_{}.sql.gz".format(db, b_datetime.isoformat())
      )

    # Create backup file
    out_file = open(path_temp, '+w')

    # Dump database to a pipe
    p_dump = subprocess.Popen(
      args + [db],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      universal_newlines=True,
      )

    # Compress data from pipe to file
    p_comp = subprocess.Popen(
      ['gzip'],
      stdin=p_dump.stdout,
      stdout=out_file,
      )

    # Wait for pipe to complete
    try:
      comp_stdout, comp_stderr = p_comp.communicate(timeout=DUMP_TIMEOUT)
      dump_stdout, dump_stderr = p_dump.communicate(timeout=DUMP_TIMEOUT)
    except subprocess.TimeoutExpired as e:
      # FIXME: Are these not killed automatically on timeout? Only the one which crashed. What about the other?
      p_comp.kill()
      p_dump.kill()
      logging.error("%s: %s", b_name, e)

      continue
    finally:
      # Close backup file
      out_file.close()
      

    if p_dump.returncode != 0 or p_comp.returncode != 0:
      logging.error("%s: Could not dump database '%s' from host '%s'", b_name, db, s.get('host'))
      logging.error(dump_stderr)
      logging.error(comp_stderr)
      continue
    else:
      logging.debug("%s: Dumped database '%s' from host '%s' to local file '%s'", b_name, db, s.get('host'), path_temp)  


    ###################
    # TRANSFER BACKUP #
    ###################
    if d['type'] == 's3':
      
      try:

        # Args to pass to rclone. Get env variables for values not supplied in config.
        rc_args = [
          'rclone',
          '--config', config['rclone_config'],
          '--s3-endpoint', d.get('endpoint', os.getenv('S3_ENDPOINT')),
          '--s3-access-key-id', d.get('access_key_id', os.getenv('S3_ACCESS_KEY_ID')),
          '--s3-secret-access-key', d.get('secret_access_key', os.getenv('S3_SECRET_ACCESS_KEY'))
          ]

        # The full path to the file on S3
        path_dest = PurePath(
          "s3:",
          d.get('bucket',os.getenv('S3_BUCKET')),
          TOP_DIR,
          b_name,
          str(b_datetime.year),
          str(b_datetime.month),
          path_temp.name # File name temp file
          )

      except KeyError as e:
        logging.error("%s: Skipping because of missing key %s in destination config", b_name, e)
        # FIXME: Delete db dump
        continue
      
      # FIXME: If debug, print out rclone version
      # rc_args + ['version']
      # rc_args + ['ls', s3_path]
      # rc_args + ['size', s3_path]

      # FIXME: Add dry-run option in config
      try:
        # Commands to perform
        commands = [
          # Make the destination dir (It may not exist)
          rc_args + ['mkdir', path_dest.parent],
          # Move the file to S3
          rc_args + ['move', path_temp, path_dest]
          ]

        # Perform commands
        for c in commands:
          # FIXME: Add timeout?
          r = subprocess.run(c, check=True)
          # FIXME: Secrets shown here!
          logging.debug("%s: %s", b_name, r)

      except subprocess.CalledProcessError as e:
        logging.error("%s: %s", b_name, e)
        # FIXME: secrets show up if we print the error here
        # FIXME: Delete db dump?
      else:
        logging.info("%s: Backed up database '%s' to %s", b_name, db, path_dest)
