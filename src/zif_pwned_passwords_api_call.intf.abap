"! <p class="shorttext synchronized" lang="en">Pwned Passwords API Wrapper</p>
INTERFACE zif_pwned_passwords_api_call
  PUBLIC .
  TYPES:
    "! Table Type - Password hash list
    tt_password_hash_list TYPE SORTED TABLE OF string WITH UNIQUE KEY table_line.

  "! <p class="shorttext synchronized" lang="en">Query the Pwned Password API</p>
  "! @parameter i_hash_prefix | <p class="shorttext synchronized" lang="en">Password Hash Prefix (1st 5 characters)</p>
  "! @parameter et_password_hashes | <p class="shorttext synchronized" lang="en">Table of matched password suffixes</p>
  "! @parameter i_use_padding | <p class="shorttext synchronized" lang="en">Enable padding (True/False)</p>
  "! @raising zcx_pwned_passwords | <p class="shorttext synchronized" lang="en"></p>
  METHODS query_pwned_passwords_api
    IMPORTING
      i_hash_prefix      TYPE string
      i_use_padding      TYPE abap_bool
    EXPORTING
      et_password_hashes TYPE tt_password_hash_list
    RAISING
      zcx_pwned_passwords.
ENDINTERFACE.
