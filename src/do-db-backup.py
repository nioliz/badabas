#!/usr/bin/env python3

import logging
import os
import subprocess

from datetime import datetime

#import tempfile
#import gzip


import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)

# Sources definition
sources = {
  'mysql': {
    'databases': [],
    'host': None,
    'password': None,
    'port': '3306',
    'user': None
    },
  }


destinations = {
  's3': {
    'access_key_id': None,
    'bucket': None,
    'endpoint': None,
    'secret_access_key': None,
    #'region': None
    },
  'local': {
    'path': None
    }
  }


# Dir to store backups
BACKUP_DIR = '/tmp'

# Default timeout when dumping database
DUMP_TIMEOUT = 60

# This is dir on the remote where backups will be stored
TOP_DIR = 'backups'

# Load configuration of backups
stream = open('./backups.yaml', 'r')
backups = yaml.safe_load(stream)

# FIXME: Define valid configs as dicts


for b_name, b_conf in backups.items():
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
      '--port=' + str(s.get('port', sources[s['type']]['port'])),
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
    
    # Name of backup file
    file_name =  "{}_{}.sql.gz".format(
      db, b_datetime.isoformat() 
      )

    # Full path to backup file
    file_path = "{}/{}".format(BACKUP_DIR, file_name)
    
    # Create backup file
    out_file = open(file_path, '+w')

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
      print(dump_stderr)
      print(comp_stderr)
    else:
      logging.debug("%s: Dumped database '%s' from host '%s' to local file '%s'", b_name, db, s.get('host'), file_name)  


    ###################
    # TRANSFER BACKUP #
    ###################
    if d['type'] == 's3':
      
      try:
        #print(d)
        # Args to pass to rclone. Get env variables for values not supplied in config.
        rc_args = [
          'rclone',
          '--config', 'rclone.conf',
          '--s3-endpoint', d.get('endpoint', os.getenv('S3_ENDPOINT')),
          '--s3-access-key-id', d.get('access_key_id', os.getenv('S3_ACCESS_KEY_ID')),
          '--s3-secret-access-key', d.get('secret_access_key', os.getenv('S3_SECRET_ACCESS_KEY'))
          ]
        # This is the path on the remote where the file will be stored
        # FIXME: these could have / in them check
        # FIXME: Use path library
        s3_path = "s3:/{}/{}/{}/{}/{}/".format(
          d['bucket'],
          TOP_DIR,
          b_name,
          b_datetime.year,
          b_datetime.month,
          )

        #print(s3_path)
      except KeyError as e:
        logging.error("%s: Skipping because of missing key %s in destination config", b_name, e)
        # FIXME: Delete db dump
        continue
      
    
      #print(rc_args)
      try:
        # FIXME: These could be looped
        a_mkdir = rc_args + ['mkdir', s3_path]
        a_ls = rc_args + ['ls', s3_path]
        a_size = rc_args + ['size', s3_path]
        a_version = rc_args + ['version']
        
        #a_move = rc_args + ['--dry-run', '--progress', 'move', file_path, s3_path]
        #a_move = rc_args + ['--progress', 'move', file_path, s3_path]
        a_move = rc_args + ['move', file_path, s3_path]
        
        
        #subprocess.run(a_version, check=True)
        
        subprocess.run(a_mkdir, check=True)
        
        subprocess.run(a_move, check=True)
        
        #subprocess.run(a_ls, check=True)
        
        #subprocess.run(a_size, check=True)
        
        
      except subprocess.CalledProcessError as e:
        logging.error("%s: %s", b_name, e)
        # FIXME: secrets show up if we print the error here
        # FIXME: Delete db dump?
      else:
        logging.info("%s: Backed up database '%s' to %s%s", b_name, db, s3_path, file_name)