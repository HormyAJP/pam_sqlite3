**pam_sqlite3 v1.0.2**
======================


Introduction
============

This module provides support to authenticate against SQLite tables for PAM-enabled applications.

This module is based on pam_sqlite, which is based on the pam_pgsql module.

Note, though, you'll probably need to use some NSS library linked to the SQlite database (like https://github.com/agamez/libnss-sqlite3) for completeness


Compilation & Installation
==========================

**1.** You will need to have SQLite and PAM library and header files for this module to compile. In practice, in Ubuntu this means having "libsqlite3-dev" and "libpam0g-dev" packages installed and, in Fedora, having "sqlite-devel" and "pam-devel" ones (besides "sqlite" package, of course)


**2.** pam_sqlite3 is autoconf'ed, thus, compiling should be a matter of:

    $ ./configure
    $ make
    $ make install

Compilation has been tested on:
- Ubuntu 22.04
- Fedora 37
- Rocky Linux 9.0 and Alma Linux 9.0
- Mac OS X 10.6.4


**3.** See test.c for an example application that authenticates using this module. You can also use the pamtester utility found here: http://pamtester.sourceforge.net


Known Issues
============

No multi-type character support


Configuration
=============

**1.-** For the service you wish the module to be used, you need to edit the /etc/pam.d/<service> file (or /etc/pam.d/common-{auth,account,password} files in Ubuntu/Debian or /etc/pam.d/systemd-auth in Fedora), and add the relevant lines. For example:

auth        required    pam_sqlite3.so 
account     required    pam_sqlite3.so
password    required    pam_sqlite3.so

*Tip: Comment any default "pam_unix.so" line if you want pam_slite3 to be the only PAM method to be used.
    
*Tip: Put "auth sufficient pam_sqlite3.so" instead of "auth required pam_sqlite3.so" before existing any default "pam_unix.so" line if you want to combine both PAM methods, one after another


**2.-** Configure the database, and table the module should use with the configuration file /etc/pam_sqlite3.conf. An example of this file:

    database = /etc/users.db
    table = accounts
    user_column = user_name
    pwd_column = user_password
    pwd_type_column = password_type
    expired_column = acc_expired
    newtok_column = acc_new_pwreq
    debug

(you should read the "Configuration Options" section in this README to know the meaning of each one).


**3.-** Once desired configuration is done, we will be already able to create the database schema. For example: 

    CREATE TABLE accounts (user_name TEXT PRIMARY KEY, user_password TEXT NOT NULL, password_type INTEGER DEFAULT 4, acc_expired TEXT DEFAULT "0", acc_new_pwreq TEXT DEFAULT "0");
    INSERT INTO accounts (user_name, user_password) VALUES ("pepe","1234");


Configuration Options
=====================

    database            - The database file which should be connected to
    table               - The name of the table to query
    user_column         - The column containing usernames
    pwd_column          - The column containing the passwords
    pw_type_column      - Specifies the password encryption scheme. Its possible value is an integer number betwen 1 and 5 (1: clear, 2: MD5, 3: SHA256, 4: SHA512, 5: CRYPT)
    expired_column      - This column should contain '1' or 'y' if the account has expired
    newtok_column       - This column should contain '1' or 'y' if the user needs to change their password
    debug               - This is a standard module option that will enable debug output to syslog (takes no values)
    config_file         - Specifies the path to a file to read for further configuration options
    sql_verify          - Specifies SQL template to use when verifying the password for a user; this query should select only the password field and does not need to be wrapped in quotes
                          Default: SELECT %Op FROM %Ot WHERE %Ou='%U'
    sql_check_expired   - SQL template to use when checking for account expiry. 
                          Default: SELECT 1 from %Ot WHERE %Ou='%U' AND (%Ox='y' OR %Ox='1')
    sql_check_newtok    - SQL template to use when checking to see if the user needs to change their password.
                          Default: SELECT 1 FROM %Ot WHERE %Ou='%U' AND (%On='y' OR %On='1')
    sql_set_passwd      - SQL template to use when updating the password for and user.
                          Default: UPDATE %Ot SET %Op='%P' WHERE %Ou='%U'

Note that for backwards compatibility with earlier versions, options specified in the configuration file can be supplied as module arguments as well. Module arguments will override the configuration file.


SQL Templates
=============

SQL templates are printf-inspired format strings. The following escape sequences are understood:

    %%       - Literal % character
    %U       - The username (provided by PAM).  It will be quoted for use in the SQL.
    %P       - The password, either entered by the user or the new password to use when changing it. It will be quoted for use in SQL.
    %O<char> - An option from the configuration; the following options are supported:
               %Ot  - value of table
               %Op  - value of pwd_column
               %Ou  - value of user_column
               %Ok  - value of password_type_column
               %Ox  - value of expired_column
               %On  - value of newtok_column
