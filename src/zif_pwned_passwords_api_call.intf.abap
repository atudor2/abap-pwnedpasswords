"! <p class="shorttext synchronized" lang="en">Pwned Passwords API Wrapper</p>
INTERFACE zif_pwned_passwords_api_call
  PUBLIC .
  TYPES:
    tt_password_hash_list TYPE SORTED TABLE OF string WITH UNIQUE KEY table_line.

  METHODS query_pwned_passwords_api
    IMPORTING
      i_hash_prefix      TYPE string
    EXPORTING
      et_password_hashes TYPE tt_password_hash_list
    RAISING
      zcx_pwned_passwords.
ENDINTERFACE.
