# abap-pwnedpasswords
Pwned Passwords implementation for ABAP

![abap package version](https://img.shields.io/endpoint?url=https://shield.abap.space/version-shield-json/github/atudor2/abap-pwnedpasswords/.apack-manifest.xml)

Built and tested with ABAP 7.52 SP01, but should work with any releases >= 7.50

## Overview
Simple ABAP wrapper for the [Pwned Passwords API V2](https://haveibeenpwned.com/api/v2#PwnedPasswords) REST API provided by Troy Hunt.

## Setup SSL
The SSL Certificates for https://api.pwnedpasswords.com/ must be added to STRUST before the API can be called. 

The [abapGit SSL Setup Guide](https://docs.abapgit.org/guide-ssl-setup.html) provides the steps to do this. 

Use the certificate from https://api.pwnedpasswords.com/ instead of [GitHub](https://github.com)

## Usage
```ABAP
  DATA(pwn_passwords) = zcl_pwned_passwords=>create( ).

  " Check if password has been Pwned:
  DATA(password) = ||.

  cl_demo_input=>request(
    EXPORTING text  = 'Enter Password:'
    CHANGING  field  = password ).

  DATA(is_pwned) = pwn_passwords->is_password_pwned( i_password = password ).

  cl_demo_output=>display(
    EXPORTING
        data = |{ COND #( WHEN is_pwned = abap_true THEN 'Password is PWNED' ELSE 'Password is safe...for now' ) }|
        name = 'IS_PWNED' ).

  " Check if password has been Pwned and get details:
  DATA(pwned_password_details) = pwn_passwords->get_password_status( i_password = password ).

  cl_demo_output=>display(
    EXPORTING
        data = pwned_password_details
        name = 'PWNED_PASSWORD_DETAILS' ).
```
