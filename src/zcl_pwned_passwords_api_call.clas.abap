"! <p class="shorttext synchronized" lang="en">Pwned Passwords API Wrapper</p>
CLASS zcl_pwned_passwords_api_call DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.
    INTERFACES zif_pwned_passwords_api_call.
  PROTECTED SECTION.
  PRIVATE SECTION.
    "! <p class="shorttext synchronized" lang="en">Rethrows the HTTP Client error message as an Exception</p>
    "! @parameter i_client | <p class="shorttext synchronized" lang="en">HTTP Client with error response</p>
    "! @raising zcx_pwned_passwords | <p class="shorttext synchronized" lang="en"></p>
    METHODS rethrow_http_client_error
      IMPORTING
        i_client TYPE REF TO if_http_client
      RAISING
        zcx_pwned_passwords.
ENDCLASS.

CLASS zcl_pwned_passwords_api_call IMPLEMENTATION.
  METHOD zif_pwned_passwords_api_call~query_pwned_passwords_api.
    DEFINE _check_error.
      IF sy-subrc <> 0.
        me->rethrow_http_client_error( client ).
      ENDIF.
    END-OF-DEFINITION.

    CLEAR et_password_hashes[].

    IF strlen( i_hash_prefix ) <> 5.
      RAISE EXCEPTION TYPE cx_abap_invalid_param_value
        EXPORTING
          value = i_hash_prefix.
    ENDIF.

    " HTTP GET to 'https://api.pwnedpasswords.com/range/{5 char hash prefix}
    cl_http_client=>create(
      EXPORTING
        host =    'api.pwnedpasswords.com'
        service = ''
        scheme  = cl_http_client=>schemetype_https
      IMPORTING
        client = DATA(client)
      EXCEPTIONS
        OTHERS = 4 ).

    IF sy-subrc <> 0.
      RAISE EXCEPTION TYPE zcx_pwned_passwords
        EXPORTING
          textid = zcx_pwned_passwords=>internal_error.
    ENDIF.

    cl_http_utility=>set_request_uri( request = client->request
                                      uri     = |/range/{ i_hash_prefix }| ).

    client->send( EXCEPTIONS OTHERS = 4 ).
    _check_error.

    client->receive( EXCEPTIONS OTHERS = 4 ).
    _check_error.

    DATA(http_response_text) = client->response->get_cdata( ).

    client->response->get_status( IMPORTING code = DATA(http_status) ).

    IF http_status <> 200.
      RAISE EXCEPTION TYPE zcx_pwned_passwords
        EXPORTING
          textid             = zcx_pwned_passwords=>malformed_api_response
          additional_message = http_response_text.
    ENDIF.

    SPLIT http_response_text AT |\r\n| INTO TABLE DATA(hash_list).

    INSERT LINES OF hash_list INTO TABLE et_password_hashes.
  ENDMETHOD.

  METHOD rethrow_http_client_error.
    i_client->get_last_error( IMPORTING message = DATA(msg) ).

    RAISE EXCEPTION TYPE zcx_pwned_passwords
      EXPORTING
        textid             = zcx_pwned_passwords=>internal_error
        additional_message = msg.
  ENDMETHOD.
ENDCLASS.
