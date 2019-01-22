"! <p class="shorttext synchronized" lang="en">Pwned Passwords</p>
INTERFACE zif_pwned_passwords
  PUBLIC .
  TYPES:
    "! Pwned Password Result structure
    BEGIN OF t_pwned_password_result,
      "! Result - ABAP_TRUE if the password has been pwned
      result TYPE abap_bool,
      "! Password usage count (0 if RESULT is not ABAP_TRUE)
      count  TYPE i,
    END OF t_pwned_password_result.

  "! <p class="shorttext synchronized" lang="en">Is the given password pwned?</p>
  "! @parameter i_password | <p class="shorttext synchronized" lang="en">Password to check</p>
  "! @parameter r_result | <p class="shorttext synchronized" lang="en">ABAP_TRUE if the password has been pwned</p>
  "! @raising zcx_pwned_passwords | <p class="shorttext synchronized" lang="en"></p>
  METHODS is_password_pwned
    IMPORTING
      i_password      TYPE string
    RETURNING
      VALUE(r_result) TYPE abap_bool
    RAISING
      zcx_pwned_passwords.

  "! <p class="shorttext synchronized" lang="en">Checks the password pwned status</p>
  "! @parameter i_password | <p class="shorttext synchronized" lang="en">Password to check</p>
  "! @parameter r_result | <p class="shorttext synchronized" lang="en">Pwned Password result struct</p>
  "! @raising zcx_pwned_passwords | <p class="shorttext synchronized" lang="en"></p>
  METHODS get_password_status
    IMPORTING
      i_password      TYPE string
    RETURNING
      VALUE(r_result) TYPE t_pwned_password_result
    RAISING
      zcx_pwned_passwords.
ENDINTERFACE.
