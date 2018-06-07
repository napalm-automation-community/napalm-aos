import paramiko
import re
import scp
import logging

try:
    from napalm.base.utils import py23_compat
    from napalm.base.exceptions import (
        ConnectionException,
        CommandErrorException,
    )
except ImportError:
    from napalm_base.utils import py23_compat
    from napalm_base.exceptions import (
        ConnectionException,
        CommandErrorException,
    )


class AlcatelOSSCPConn(object):
    """
    Establish a secure copy channel to the remote network device.

    Must close the SCP connection to get the file to write to the remote filesystem
    """
    def __init__(self, ssh_conn):
        self.ssh_ctl_chan = ssh_conn
        self.establish_scp_conn()

    def establish_scp_conn(self):
        """Establish the secure copy connection."""
        ssh_connect_params = self.ssh_ctl_chan.get_configured_param()
        self.scp_conn = paramiko.SSHClient()
        self.scp_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.scp_conn.connect(**ssh_connect_params)
        self.scp_client = scp.SCPClient(self.scp_conn.get_transport())

    def scp_transfer_file(self, source_file, dest_file):
        """Put file using SCP (for backwards compatibility)."""
        self.scp_client.put(source_file, dest_file)

    def scp_get_file(self, source_file, dest_file):
        """Get file using SCP."""
        self.scp_client.get(source_file, dest_file)

    def scp_put_file(self, source_file, dest_file):
        """Put file using SCP."""
        self.scp_client.put(source_file, dest_file)

    def close(self):
        """Close the SCP connection."""
        if self.scp_conn:
            self.scp_conn.close()


class AlcatelOS(object):

    def __init__(self, hostname, username=None, password=None, timeout=60, optional_args=None):
        self.ssh = None

        if optional_args is None:
            optional_args = {}

        # Paramiko possible arguments
        self.paramiko_cfg = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'timeout': timeout,
            'port': 22,
            'pkey': None,
            'key_filename': None,
            'allow_agent': True,
            'look_for_keys': True,
            'compress': False,
            'sock': None,
            'gss_auth': False,
            'gss_kex': False,
            'gss_deleg_creds': True,
            'gss_host': None,
            'banner_timeout': None,
            'auth_timeout': None,
            'gss_trust_dns': True,
            'passphrase': None
        }

        # Build dict of any optional args
        for k, v in self.paramiko_cfg.items():
            try:
                self.paramiko_cfg[k] = optional_args[k]
            except KeyError:
                pass

    def get_configured_param(self):
        return self.paramiko_cfg

    def is_alive(self):
        return self.ssh.get_transport().is_active()

    def open(self):
        """
        Opens the ssh session with the device.
        """
        logging.debug('Connecting to device %s' % self.paramiko_cfg.get('hostname'))
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(**self.paramiko_cfg)

    def close(self):
        """
        Closes the ssh session with the device.
        """
        logging.debug('Closing connection to device %s' % self.paramiko_cfg.get('hostname'))
        if self.ssh:
            self.ssh.close()

    @staticmethod
    def _read_wrapper(data):
        """Ensure unicode always returned on read."""
        # Paramiko (strangely) in PY3 returns an int here.
        if isinstance(data, int):
            data = chr(data)
        # Ensure unicode
        return py23_compat.text_type(data)

    def send_command_non_blocking(self, command, timeout=60, throw_exception=True):
        logging.debug('Executing commands:\n %s' % command)
        if not self.ssh:
            raise ConnectionException('Device not open')

        stdin, stdout, stderr = self.ssh.exec_command(command, timeout=timeout)
        output = ''.join(stdout.readlines())
        error = ''.join(stderr.readlines())

        if len(error) > 0:
            msg = '%s:%s' % (command, error)
            logging.debug('error:' + msg)
            if throw_exception:
                raise CommandErrorException(msg)

        regex = re.compile('ERROR:')
        if len(regex.findall(output)) > 0:
            msg = '%s:%s' % (command, output)
            logging.debug('error:' + msg)
            if throw_exception:
                raise CommandErrorException(msg)

        return output[:-1], error[:-1]  # Remove last newline charater.

    def send_command(self, command, timeout=60, throw_exception=True):
        output, error, retCode = self.send_command_std(command, timeout, throw_exception)
        return output

    def send_command_std(self, command, timeout=60, throw_exception=True):
        logging.debug('Executing commands:\n %s' % command)
        if not self.ssh:
            raise ConnectionException('Device not open')

        chan = self.ssh.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        retcode = chan.recv_exit_status()
        logging.debug('Command exited with code %d' % retcode)

        error_chan = chan.makefile_stderr()
        output_chan = chan.makefile()

        error = ''
        output = ''

        for e in error_chan.read():
            error = error + self._read_wrapper(e)

        logging.debug("stderr: " + error)

        for o in output_chan.read():
            output = output + self._read_wrapper(o)

        logging.debug("stdout: " + output)

        # Ignore stty error happen in some devices
        if "stty: standard input: Inappropriate ioctl for device" in error:
            error = error.replace('stty: standard input: Inappropriate ioctl for device\n', '')

        if len(error) > 0 and retcode != 0:
            msg = '%s:%s' % (command, error)
            logging.debug('error:' + msg)
            if throw_exception:
                raise CommandErrorException(msg)

        regex = re.compile('ERROR:')
        if len(regex.findall(output)) > 0:
            msg = '%s:%s' % (command, output)
            logging.debug('error:' + msg)
            if throw_exception:
                raise CommandErrorException(msg)
        return output[:-1], error[:-1], retcode  # Remove last newline charater.
