#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
backup-and-encrypt-remote-files.py

Description:
This script is used to backup remote servers using rsync and gocryptfs.
It reads backup.ini files under the backup_root directory and performs
backup of the remote servers specified in the backup.ini files.

Pre-requisites:
- gocryptfs
- rsync
- ssh

Usage:
backup.py [--backup-root BACKUP_ROOT] [--loglevel LOGLEVEL] [--dry-run] [--redirect] [group] [host]

Author: Tomoatsu Shimada
Date: 2024-07-11
Version: 1.0

Copyright (c) 2024 Tomoatsu Shimada
All rights reserved.

License: MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
IN THE SOFTWARE.
"""

import os,sys,logging,argparse,tempfile,subprocess,glob,configparser

BACKUP_ROOT = "/var/backup"
DONE_FILE = "backup.done"
PASSWORD_ENV = "BACKUP_PASSWORD"

class DynamicStreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()

    @property
    def stream(self):
        return self._stream

    @stream.setter
    def stream(self, value):
        self._stream = value
    
    def emit(self, record):
        self.stream = sys.stderr if record.levelno >= logging.ERROR else sys.stdout
        super().emit(record)

class MountBackup:
    def __init__(self, backup_dir, mountpoint, password):
        self.backup_dir = backup_dir
        self.mountpoint = mountpoint
        self.password = password
    def __enter__(self):
        # error if already mounted
        if subprocess.run(["mountpoint", "-q", self.mountpoint]).returncode == 0:
            raise RuntimeError("Backup already mounted")
        os.makedirs(self.mountpoint, exist_ok=True)
        logging.debug("Mounting the backup")
        with tempfile.NamedTemporaryFile() as passfile:
            passfile.write(self.password.encode())
            passfile.flush()
            subprocess.check_call(["gocryptfs", "-passfile", passfile.name, self.backup_dir, self.mountpoint], stdout=sys.stdout, stderr=sys.stderr)
        return self.mountpoint
    def __exit__(self, exc_type, exc_value, traceback):
        logging.debug("Unmounting the backup")
        subprocess.check_call(["umount", self.mountpoint])

class RedirectStdStreams:
    def __init__(self, stdout=None, stderr=None):
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self.stdout, self.stderr
    def __exit__(self, exc_type, exc_value, traceback):
        self.stdout.flush(); self.stderr.flush()
        sys.stdout, sys.stderr = self.old_stdout, self.old_stderr

def initialize_encrypted_dir(files_dir, password):
    os.makedirs(files_dir, exist_ok=False) # error if already exists
    with tempfile.NamedTemporaryFile() as passfile:
        passfile.write(password.encode())
        passfile.flush()
        subprocess.check_call(["gocryptfs", "-init", "-q", "-passfile", passfile.name, files_dir], stdout=sys.stdout, stderr=sys.stderr)

def do_backup(backup_dir, password, dry_run=False):
    inifile = os.path.join(backup_dir, "backup.ini")
    config = configparser.ConfigParser()
    config.read(inifile)

    remote_host = config.get("remote", "host", fallback=os.path.basename(backup_dir))
    remote_user = config.get("remote", "user", fallback="root")
    remote_type = config.get("remote", "type", fallback=None)
    rsync_excludes = os.path.join(backup_dir, "rsync-excludes")
    if not os.path.isfile(rsync_excludes): rsync_excludes = None
    remote_host_rsync = '[' + remote_host + ']' if ':' in remote_host else remote_host
    logging.info("Remote host: %s, user: %s, backup dir: %s", remote_host, remote_user, backup_dir)

    files_dir = os.path.join(backup_dir, "files")
    mountpoint = os.path.join(backup_dir, "files.tmp")
    if not os.path.exists(files_dir):
        logging.info("Creating encrypted directory %s", files_dir)
        initialize_encrypted_dir(files_dir, password)
    if not os.path.isdir(mountpoint): os.makedirs(mountpoint)

    rsync_cmdline = ["rsync", "-avx", "--no-specials", "--no-devices", "-e", "ssh -o StrictHostKeyChecking=no", "--delete"]
    if dry_run: rsync_cmdline += ["--dry-run"]
    if rsync_excludes is not None: rsync_cmdline += ["--exclude-from=%s" % rsync_excludes]
    rsync_src = f"{remote_user}@{remote_host_rsync}:/"
    if remote_type == "genpack":
        rsync_cmdline += ["--exclude=/swapfile","--exclude=/mysql","--delete-excluded"]
        rsync_src = f"{remote_user}@{remote_host_rsync}:/run/initramfs/rw/"

    logging.info("Mounting backup")
    try:
        with MountBackup(files_dir, mountpoint, password) as files_dest_dir:
            rsync_cmdline += [rsync_src, files_dest_dir]
            subprocess.check_call(rsync_cmdline, stderr=sys.stderr, stdout=sys.stdout)
    finally:
        logging.info("Backup unmounted")

def main(backup_root, password, redirect, dry_run, group, host):
    backup_inifiles = glob.glob(os.path.join(group, host, "backup.ini"), root_dir=backup_root)
    if not backup_inifiles:
        logging.error("No backup.ini files found with group %s and host %s", group, host)
        return False
    all_success = True
    for backup_inifile in backup_inifiles:
        logging.info("Processing %s", backup_inifile)
        path_splitted = backup_inifile.split(os.sep)
        backup_group = path_splitted[0]
        remote_host = path_splitted[1]
        backup_dir = os.path.join(backup_root, backup_group, remote_host)
        log_stdout = open(os.path.join(backup_root, backup_group, remote_host, "backup.log"), "w") if redirect else sys.stdout
        log_stderr = open(os.path.join(backup_root, backup_group, remote_host, "backup.err"), "w") if redirect else sys.stderr
        try:
            with RedirectStdStreams(stdout=log_stdout, stderr=log_stderr):
                do_backup(backup_dir, password,dry_run=dry_run)
            if redirect:
                    log_stdout.close()
                    log_stderr.close()
            logging.info("Done processing %s", backup_inifile)
        except Exception as e:
            logging.error("Error processing %s: %s", backup_inifile, str(e))
            all_success = False
    return all_success

def ask_password(prompt):
    password = input(prompt).strip()
    if password == "": password = None
    return password

if __name__ == '__main__':
    # read password from environment variable and remove it as soon as possible
    password = None
    if PASSWORD_ENV in os.environ: 
        password = os.environ[PASSWORD_ENV]
        del os.environ[PASSWORD_ENV]

    # parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-root", help="set backup root", default=BACKUP_ROOT)
    parser.add_argument("--loglevel", help="set log level", default="INFO")
    parser.add_argument("--dry-run", help="do not perform the backup", action="store_true")
    parser.add_argument("--redirect", help="redirect stdout and stderr regardless tty is attached", action="store_true")
    # group, host positional arguments are optional and defalut is "*"
    parser.add_argument("group", help="set group", nargs="?", default="*")
    parser.add_argument("host", help="set host", nargs="?", default="*")
    args = parser.parse_args()

    backup_root = args.backup_root
    # redirect stdout and stderr if tty is not attached
    redirect = not sys.stdout.isatty()
    # even not, redirect if --redirect option is specified
    if args.redirect: redirect = True

    log_stdout = sys.stdout
    log_stderr = sys.stderr
    done_file = os.path.join(backup_root, DONE_FILE)
    if redirect:
        # remove done_file under backup_root if exists
        if os.path.exists(done_file): os.remove(done_file)
        logger = logging.getLogger()
        logger.setLevel(args.loglevel)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        handler = DynamicStreamHandler()
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        # open log files in append mode.  create if not exists
        log_stdout = open(os.path.join(backup_root, "backup.log"), "a")
        log_stderr = open(os.path.join(backup_root, "backup.err"), "a")
    else:
        logging.basicConfig(level=args.loglevel)

    logging.debug(args)

    code = 0
    with RedirectStdStreams(stdout=log_stdout, stderr=log_stderr):
        try:
            if password is None:
                if redirect: logging.error("Environment variable %s is not set" % PASSWORD_ENV)
                else: password = ask_password("Enter password: ")
            if password is None:
                raise RuntimeError("Password is not given")
            if not main(backup_root, password, redirect,args.dry_run, args.group, args.host):
                code = 2
        except Exception as e:
            logging.error(str(e))
            code = 1
    if redirect:
        log_stdout.close()
        log_stderr.close()
        # create done file under backup_root
        if code == 0: 
            with open(done_file, "w"): pass

    exit(code)
