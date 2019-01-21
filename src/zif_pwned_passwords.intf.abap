"! <p class="shorttext synchronized" lang="en">Pwned Passwords</p>
INTERFACE zif_pwned_passwords
  PUBLIC .
  TYPES:
    BEGIN OF t_pwned_password_result,
      result TYPE abap_bool,
      count  TYPE i,
    END OF t_pwned_password_result.

  METHODS is_pwned_password
    IMPORTING
      i_password      TYPE string
    RETURNING
      VALUE(r_result) TYPE abap_bool
    RAISING
      zcx_pwned_passwords.

  METHODS query_password
    IMPORTING
      i_password      TYPE string
    RETURNING
      VALUE(r_result) TYPE t_pwned_password_result
    RAISING
      zcx_pwned_passwords.
ENDINTERFACE.
