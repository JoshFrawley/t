# Run all our standard hardening
---

- name: QCyber - Hardening Script
  hosts: localhost
  vars:
    admin_user: "qcadmin"
    password_hash: "$6$YV6XhpxcdtIsO$C8jX.tgidDRmjnoY1j/.qAdX4VfuwAyuIXRMgg..TO7dWM5Js1VgPWft/ChLHB./FIfD4XM6xR.jUwt8ZduCI."
    openssh_key: "AAAAB3NzaC1yc2EAAAADAQABAAABgQCpQJftUej0PnB7POsBOnYu5uzCypWtwKtRNJlfgUfoYlipgcH4d69C6puPUhLipWp+ZxJ1MiPJub7sfa4g5Ybg2JwWJFMqrb7FwqSk1Fsf7ij6xBbspg+ie+enCwyd5Tl4EIqm2VzhhcZ1LZzqIvkawt9HYTxoSXHZrhLs5b16QPEFp7ED8C/Lsa+oYGWa0H31LU+RGxE/gc4sZjMeBmFfEpaz5lHSaL6d5pdgl4JGEvZhgxL1sJSZdjQ6fAAE8QGhJPIAqiDbRs9krFO+YNprkRKmHpT3vKbWtnX23FDtSX1nriQKdZ2qj7J/KKPIDM4A4ULCKsROBkrD60Uud+Lu38dXa9XAuz1KfCDOwbpxcfweDlzlJ2+aJKe77rGsPXg13FGr7PICrEoM7/0jRtx5z5vlIabIEVuvLDSwUdhkc2OgPs82LVQ6OxYg7Kc51xi53IgRODRB4iZUZWhMKg/6blOCx45kIOl6CKZUO/QsxNJ3LIxNJoV44zV7S42ruiM="
    oms_url: "https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh"
    oms_bin: "/tmp/onboard_agent.sh"
    cef_url: "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_installer.py"
    cef_bin: "/tmp/cef_installer.py"

  tasks:
  - name: Create group
    group: 
      name: "{{ admin_user }}"

  - name: Create user
    user:
      name: "{{ admin_user }}"
      password: "{{ password_hash }}"
      groups:
        - adm
        - sudo
        - "{{ admin_user }}"
      state: present
      shell: /bin/bash
      system: no
      createhome: yes
      home: /home/{{ admin_user }}

  - name: Configure SSH directory
    file:
      path: /home/{{ admin_user }}/.ssh
      state: directory
      mode: 0700
      owner: "{{ admin_user }}"
      group: "{{ admin_user }}"
  
  - name: Configure SSH key
    copy:
      dest: /home/{{ admin_user }}/.ssh/authorized_keys
      mode: 0600
      owner: "{{ admin_user }}"
      group: "{{ admin_user }}"
      content: |
        {{ openssh_key }}
  
  - name: Download OMS Agent
    get_url: 
       url: "{{ oms_url }}"
       dest: "{{ oms_bin }}"
       mode: '0400'

  - name: Run installer
    become: yes
    become_method: sudo
    command: sh "{{ oms_bin }}" -w "{{ workspace_id }}" -s "{{ secret_key }}" -d opinsights.azure.com

  - name: Download CEF installer
    get_url:
       url: "{{ cef_url }}"
       dest: "{{ cef_bin }}"
       mode: '0400'

  - name: Run CEF installer
    become: yes
    become_method: sudo
    command: python "{{ cef_bin }}" "{{ workspace_id }}" "{{ secret_key }}"

  - name: Checking file
    stat: path=/etc/rsyslog.d/security-config-omsagent.conf
    register: cef_defaults

  - name: Update filename (priority)
    command: mv /etc/rsyslog.d/security-config-omsagent.conf /etc/rsyslog.d/40-QCyber-CEF.conf
    when: cef_defaults.stat.exists

  - name: Update configuration
    lineinfile:
      path: /etc/rsyslog.d/40-QCyber-CEF.conf
      line: "& stop" 

  - name: Tell user to restart service
    debug: 
      msg: "Please restart the OMS Agent service now"
  
  - name: Install auditd
    apt:
      name: auditd
      state: present

  - name: Backup existing OSSEC configuration file
    command:
      mv /etc/audit/auditd.conf /etc/audit/auditd.conf.ORIG

  - name: Auditd configuration
    blockinfile:
      create: yes
      insertafter: EOF
      path: /etc/audit/auditd.conf
      block: |
        #
        # This file controls the configuration of the audit daemon
        #

        local_events = yes
        write_logs = yes
        log_file = /var/log/audit/audit.log
        log_group = adm
        log_format = RAW
        flush = INCREMENTAL_ASYNC
        freq = 50
        max_log_file = 8
        num_logs = 5
        priority_boost = 4
        disp_qos = lossy
        dispatcher = /sbin/audispd
        name_format = NONE
        ##name = mydomain
        max_log_file_action = ROTATE
        space_left = 75
        space_left_action = SYSLOG
        verify_email = yes
        action_mail_acct = root
        admin_space_left = 50
        admin_space_left_action = SUSPEND
        disk_full_action = SUSPEND
        disk_error_action = SUSPEND
        use_libwrap = yes
        ##tcp_listen_port = 60
        tcp_listen_queue = 5
        tcp_max_per_addr = 1
        ##tcp_client_ports = 1024-65535
        tcp_client_max_idle = 0
        enable_krb5 = no
        krb5_principal = auditd
        ##krb5_key_file = /etc/audit/audit.key
        distribute_network = no


  - name: Quorum Cyber rules
    blockinfile:
      create: yes
      insertafter: EOF
      path: /etc/audit/rules.d/qcyber.rules
      block: |
        # Quorum Cyber Auditd
        #      ___             ___ __      __
        #     /   | __  ______/ (_) /_____/ /
        #    / /| |/ / / / __  / / __/ __  /
        #   / ___ / /_/ / /_/ / / /_/ /_/ /
        #  /_/  |_\__,_/\__,_/_/\__/\__,_/
        #
        # Linux Audit Daemon - Best Practice Configuration
        # /etc/audit/audit.rules
        #
        # Compiled by Florian Roth
        #
        # Created  : 2017/12/05
        # Modified : 2019/11/26
        #
        # Based on rules published here:
        #   Gov.uk auditd rules
        #   	https://github.com/gds-operations/puppet-auditd/pull/1
        # 	CentOS 7 hardening
        # 		https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon
        # 	Linux audit repo
        # 		https://github.com/linux-audit/audit-userspace/tree/master/rules
        # 	Auditd high performance linux auditing
        # 		https://linux-audit.com/tuning-auditd-high-performance-linux-auditing/
        #
        # Further rules
        # 	For PCI DSS compliance see:
        # 		https://github.com/linux-audit/audit-userspace/blob/master/rules/30-pci-dss-v31.rules
        # 	For NISPOM compliance see:
        # 		https://github.com/linux-audit/audit-userspace/blob/master/rules/30-nispom.rules

        # Remove any existing rules
        -D

        # Buffer Size
        ## Feel free to increase this if the machine panic's
        -b 8192

        # Failure Mode
        ## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
        -f 1

        # Ignore errors
        ## e.g. caused by users or files not found in the local environment
        -i

        # Self Auditing ---------------------------------------------------------------

        ## Audit the audit logs
        ### Successful and unsuccessful attempts to read information from the audit records
        -w /var/log/audit/ -k auditlog

        ## Auditd configuration
        ### Modifications to audit configuration that occur while the audit collection functions are operating
        -w /etc/audit/ -p wa -k auditconfig
        -w /etc/libaudit.conf -p wa -k auditconfig
        -w /etc/audisp/ -p wa -k audispconfig

        ## Monitor for use of audit management tools
        -w /sbin/auditctl -p x -k audittools
        -w /sbin/auditd -p x -k audittools

        # Filters ---------------------------------------------------------------------

        ### We put these early because audit is a first match wins system.

        ## Ignore SELinux AVC records
        -a always,exclude -F msgtype=AVC

        ## Ignore current working directory records
        -a always,exclude -F msgtype=CWD

        ## Ignore EOE records (End Of Event, not needed)
        -a always,exclude -F msgtype=EOE

        ## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
        -a never,user -F subj_type=crond_t
        -a never,exit -F subj_type=crond_t

        ## This prevents chrony from overwhelming the logs
        -a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=_chrony -F subj_type=chronyd_t

        ## This is not very interesting and wastes a lot of space if the server is public facing
        -a always,exclude -F msgtype=CRYPTO_KEY_USER

        ## VMWare tools
        -a never,exit -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
        -a never,exit -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

        ### High Volume Event Filter (especially on Linux Workstations)
        -a never,exit -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
        -a never,exit -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
        -a never,exit -F arch=b32 -F dir=/var/lock/lvm -k locklvm
        -a never,exit -F arch=b64 -F dir=/var/lock/lvm -k locklvm

        ## More information on how to filter events
        ### https://access.redhat.com/solutions/2482221

        # Rules -----------------------------------------------------------------------

        ## Kernel parameters
        -w /etc/sysctl.conf -p wa -k sysctl

        ## Kernel module loading and unloading
        -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
        -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
        -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
        -a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
        -a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
        ## Modprobe configuration
        -w /etc/modprobe.conf -p wa -k modprobe

        ## KExec usage (all actions)
        -a always,exit -F arch=b64 -S kexec_load -k KEXEC
        -a always,exit -F arch=b32 -S sys_kexec_load -k KEXEC

        ## Special files
        -a always,exit -F arch=b32 -S mknod -S mknodat -k specialfiles
        -a always,exit -F arch=b64 -S mknod -S mknodat -k specialfiles

        ## Mount operations (only attributable)
        -a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount
        -a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount

        # Change swap (only attributable)
        -a always,exit -F arch=b64 -S swapon -S swapoff -F auid!=-1 -k swap
        -a always,exit -F arch=b32 -S swapon -S swapoff -F auid!=-1 -k swap

        ## Time
        -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
        -a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
        ### Local time zone
        -w /etc/localtime -p wa -k localtime

        ## Stunnel
        -w /usr/sbin/stunnel -p x -k stunnel

        ## Cron configuration & scheduled jobs
        -w /etc/cron.allow -p wa -k cron
        -w /etc/cron.deny -p wa -k cron
        -w /etc/cron.d/ -p wa -k cron
        -w /etc/cron.daily/ -p wa -k cron
        -w /etc/cron.hourly/ -p wa -k cron
        -w /etc/cron.monthly/ -p wa -k cron
        -w /etc/cron.weekly/ -p wa -k cron
        -w /etc/crontab -p wa -k cron
        -w /var/spool/cron/crontabs/ -k cron

        ## User, group, password databases
        -w /etc/group -p wa -k etcgroup
        -w /etc/passwd -p wa -k etcpasswd
        -w /etc/gshadow -k etcgroup
        -w /etc/shadow -k etcpasswd
        -w /etc/security/opasswd -k opasswd

        ## Sudoers file changes
        -w /etc/sudoers -p wa -k actions
        -w /etc/sudoers.d/ -p wa -k actions

        ## Passwd
        -w /usr/bin/passwd -p x -k passwd_modification

        ## Tools to change group identifiers
        -w /usr/sbin/groupadd -p x -k group_modification
        -w /usr/sbin/groupmod -p x -k group_modification
        -w /usr/sbin/addgroup -p x -k group_modification
        -w /usr/sbin/useradd -p x -k user_modification
        -w /usr/sbin/usermod -p x -k user_modification
        -w /usr/sbin/adduser -p x -k user_modification

        ## Login configuration and information
        -w /etc/login.defs -p wa -k login
        -w /etc/securetty -p wa -k login
        -w /var/log/faillog -p wa -k login
        -w /var/log/lastlog -p wa -k login
        -w /var/log/tallylog -p wa -k login

        ## Network Environment
        ### Changes to hostname
        -a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
        -a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
        ## Successful IPv4 Connections
        -a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -F key=network_connect_4
        -a always,exit -F arch=b32 -S connect -F a2=16 -F success=1 -F key=network_connect_4
        ## Successful IPv6 Connections
        -a always,exit -F arch=b64 -S connect -F a2=28 -F success=1 -F key=network_connect_6
        -a always,exit -F arch=b32 -S connect -F a2=28 -F success=1 -F key=network_connect_6
        ### Changes to other files
        -w /etc/hosts -p wa -k network_modifications
        -w /etc/sysconfig/network -p wa -k network_modifications
        -w /etc/network/ -p wa -k network
        -a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications
        ### Changes to issue
        -w /etc/issue -p wa -k etcissue
        -w /etc/issue.net -p wa -k etcissue

        ## System startup scripts
        -w /etc/inittab -p wa -k init
        -w /etc/init.d/ -p wa -k init
        -w /etc/init/ -p wa -k init

        ## Library search paths
        -w /etc/ld.so.conf -p wa -k libpath

        ## Systemwide library preloads (LD_PRELOAD)
        -w /etc/ld.so.preload -p wa -k systemwide_preloads

        ## Pam configuration
        -w /etc/pam.d/ -p wa -k pam
        -w /etc/security/limits.conf -p wa  -k pam
        -w /etc/security/pam_env.conf -p wa -k pam
        -w /etc/security/namespace.conf -p wa -k pam
        -w /etc/security/namespace.init -p wa -k pam

        ## Mail configuration
        -w /etc/aliases -p wa -k mail

        ## SSH configuration
        -w /etc/ssh/sshd_config -k sshd

        # Systemd
        -w /bin/systemctl -p x -k systemd
        -w /etc/systemd/ -p wa -k systemd

        ## SELinux events that modify the system's Mandatory Access Controls (MAC)
        -w /etc/selinux/ -p wa -k mac_policy

        ## Critical elements access failures
        -a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
        -a always,exit -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess

        ## Process ID change (switching accounts) applications
        -w /bin/su -p x -k priv_esc
        -w /usr/bin/sudo -p x -k priv_esc
        -w /etc/sudoers -p rw -k priv_esc

        ## Power state
        -w /sbin/shutdown -p x -k power
        -w /sbin/poweroff -p x -k power
        -w /sbin/reboot -p x -k power
        -w /sbin/halt -p x -k power

        ## Session initiation information
        -w /var/run/utmp -p wa -k session
        -w /var/log/btmp -p wa -k session
        -w /var/log/wtmp -p wa -k session

        ## Discretionary Access Control (DAC) modifications
        -a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
        -a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

        # Special Rules ---------------------------------------------------------------

        ## 32bit API Exploitation
        ### If you are on a 64 bit platform, everything _should_ be running
        ### in 64 bit mode. This rule will detect any use of the 32 bit syscalls
        ### because this might be a sign of someone exploiting a hole in the 32
        ### bit API.
        -a always,exit -F arch=b32 -S all -k 32bit_api

        ## Reconnaissance
        -w /usr/bin/whoami -p x -k recon
        -w /usr/bin/id -p x -k recon
        -w /bin/hostname -p x -k recon
        -w /bin/uname -p x -k recon
        -w /etc/issue -p r -k recon
        -w /etc/hostname -p r -k recon

        ## Suspicious activity
        -w /usr/bin/wget -p x -k susp_activity
        -w /usr/bin/curl -p x -k susp_activity
        -w /usr/bin/base64 -p x -k susp_activity
        -w /bin/nc -p x -k susp_activity
        -w /bin/netcat -p x -k susp_activity
        -w /usr/bin/ncat -p x -k susp_activity
        -w /usr/bin/ssh -p x -k susp_activity
        -w /usr/bin/scp -p x -k susp_activity
        -w /usr/bin/sftp -p x -k susp_activity
        -w /usr/bin/ftp -p x -k susp_activity
        -w /usr/bin/socat -p x -k susp_activity
        -w /usr/bin/wireshark -p x -k susp_activity
        -w /usr/bin/tshark -p x -k susp_activity
        -w /usr/bin/rawshark -p x -k susp_activity
        -w /usr/bin/rdesktop -p x -k susp_activity
        -w /usr/bin/nmap -p x -k susp_activity

        ## Added to catch netcat on Ubuntu
        -w /bin/nc.openbsd -p x -k susp_activity
        -w /bin/nc.traditional -p x -k susp_activity

        ## Sbin suspicious activity
        -w /sbin/iptables -p x -k sbin_susp
        -w /sbin/ip6tables -p x -k sbin_susp
        -w /sbin/ifconfig -p x -k sbin_susp
        -w /usr/sbin/arptables -p x -k sbin_susp
        -w /usr/sbin/ebtables -p x -k sbin_susp
        -w /usr/sbin/nft -p x -k sbin_susp
        -w /usr/sbin/tcpdump -p x -k sbin_susp
        -w /usr/sbin/traceroute -p x -k sbin_susp
        -w /usr/sbin/ufw -p x -k sbin_susp

        ## Injection
        ### These rules watch for code injection by the ptrace facility.
        ### This could indicate someone trying to do something bad or just debugging
        -a always,exit -F arch=b32 -S ptrace -k tracing
        -a always,exit -F arch=b64 -S ptrace -k tracing
        -a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
        -a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
        -a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
        -a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
        -a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
        -a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

        ## Privilege Abuse
        ### The purpose of this rule is to detect when an admin may be abusing power by looking in user's home dir.
        -a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse

        # Software Management ---------------------------------------------------------

        # DPKG / APT-GET (Debian/Ubuntu)
        -w /usr/bin/dpkg -p x -k software_mgmt
        -w /usr/bin/apt -p x -k software_mgmt
        -w /usr/bin/apt-add-repository -p x -k software_mgmt
        -w /usr/bin/apt-get -p x -k software_mgmt
        -w /usr/bin/aptitude -p x -k software_mgmt
        -w /usr/bin/wajig -p x -k software_mgmt
        -w /usr/bin/snap -p x -k software_mgmt

        # PIP (Python installs)
        -w /usr/bin/pip -p x -k software_mgmt
        -w /usr/bin/pip3 -p x -k software_mgmt

        # Special Software ------------------------------------------------------------

        ## GDS specific secrets
        -w /etc/puppet/ssl -p wa -k puppet_ssl

        ## IBM Bigfix BESClient
        -a always,exit -F arch=b64 -S open -F dir=/opt/BESClient -F success=0 -k soft_besclient
        -w /var/opt/BESClient/ -p wa -k soft_besclient

        ## CHEF https://www.chef.io/chef/
        -w /etc/chef -p wa -k soft_chef

        ### Docker
        -w /usr/bin/dockerd -k docker
        -w /usr/bin/docker -k docker
        -w /usr/bin/docker-containerd -k docker
        -w /usr/bin/docker-runc -k docker
        -w /var/lib/docker -k docker
        -w /etc/docker -k docker
        -w /etc/sysconfig/docker -k docker
        -w /etc/sysconfig/docker-storage -k docker
        -w /usr/lib/systemd/system/docker.service -k docker

        # High volume events ----------------------------------------------------------

        ## Remove them if they cause to much volume in your environment

        ## Root command executions
        -a always,exit -F arch=b64 -F euid=0 -S execve -k rootcmd
        -a always,exit -F arch=b32 -F euid=0 -S execve -k rootcmd

        ## File Deletion Events by User
        -a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
        -a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

        ## File Access
        ### Unauthorized Access (unsuccessful)
        -a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
        -a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access
        -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
        -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access

        ### Unsuccessful Creation
        -a always,exit -F arch=b32 -S creat,link,mknod,mkdir,symlink,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
        -a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
        -a always,exit -F arch=b32 -S link,mkdir,symlink,mkdirat -F exit=-EPERM -k file_creation
        -a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

        ### Unsuccessful Modification
        -a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
        -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
        -a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification
        -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification

        # Make the configuration immutable --------------------------------------------
        ##-e 2

  - name : Install GPG Dependency
    apt: name=gnupg2 state=latest

  - name : Install Python Dependency
    apt: name=python3-apt state=latest

  - name : Add OSSEC GPG apt Key
    apt_key:
      url=https://www.atomicorp.com/RPM-GPG-KEY.atomicorp.txt
      state=present

  - name: Disable host based auth
    lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^[\s\t]*HostbasedAuthentication\s(yes|no)'
      insertafter: '^#HostbasedAuthentication'
      line: HostbasedAuthentication no
      state: present

  - name: Disable root login
    lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^PermitRootLogin\s(yes|no|prohibit-password)'
      insertafter: '^#PermitRootLogin'
      line: PermitRootLogin no
      state: present

  - name: Dont permit empty passwords
    lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^PermitEmptyPasswords\s(yes|no)'
      insertafter: '^#PermitEmptyPasswords'
      line: PermitEmptyPasswords no
      state: present

  - name: Ignore Rhosts
    lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^\s*IgnoreRhosts\s(yes|no)'
      insertafter: '^#IgnoreRhosts'
      line: IgnoreRhosts yes

  - name: Force Protocol 2
    lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^\s*Protocol\s(1|2)'
      insertafter: '^#Protocol'
      line: Protocol 2
    
  - name: Update configuration
    blockinfile:
      create: no
      insertafter: EOF
      path: /etc/bash.bashrc
      block: |
        # Log commands to syslog
        function h2l { echo -n "CEF: 0|QCyber|Bash Logging|v0.1|602|Command run by user|3|dvc=$(hostname -f) cs1Label=Location cs1=$(hostname -f)->/var/log/syslog classification= syslog,commands, msg=$USER ($PWD) $BASH_COMMAND" | grep -v -e "echo -ne "| logger -p local1.notice -i ; }
        trap h2l DEBUG

  - name: Install packages
    apt:
      name={{ item }}
      state=present
      update_cache=yes
    with_items:
      - unattended-upgrades
      - update-notifier-common

  - name: Backup configuration
    command:
      mv /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.BACKUP

  - name: Update configuration
    blockinfile:
      create: yes
      insertafter: EOF
      path: /etc/apt/apt.conf.d/50unattended-upgrades
      block: |
        // Automatically upgrade packages from these (origin:archive) pairs
        //
        // Note that in Ubuntu security updates may pull in new dependencies
        // from non-security sources (e.g. chromium). By allowing the release
        // pocket these get automatically pulled in.
        Unattended-Upgrade::Allowed-Origins {
                "${distro_id}:${distro_codename}";
                "${distro_id}:${distro_codename}-security";
                "${distro_id}ESMApps:${distro_codename}-apps-security";
                "${distro_id}ESM:${distro_codename}-infra-security";
        };

        Unattended-Upgrade::Package-Blacklist {
        //      "libc6-i686";
        };

        Unattended-Upgrade::DevRelease "false";
        Unattended-Upgrade::AutoFixInterruptedDpkg "true";
        Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
        Unattended-Upgrade::Remove-Unused-Dependencies "true";
        Unattended-Upgrade::Automatic-Reboot "true";
        Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
        Unattended-Upgrade::Automatic-Reboot-Time "00:25";
        Unattended-Upgrade::SyslogEnable "true";
        Unattended-Upgrade::SyslogFacility "daemon";
    notify:
      - Restart Service

  handlers:
    - name: Restart Service
      service:
          name: "unattended-upgrades"
          state: restarted
