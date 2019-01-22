"! <p class="shorttext synchronized" lang="en">Pwned Passwords</p>
CLASS zcl_pwned_passwords DEFINITION
  PUBLIC
  CREATE PUBLIC .

  PUBLIC SECTION.
    INTERFACES zif_pwned_passwords.

    "! <p class="shorttext synchronized" lang="en">Creates a new instance of the Pwned Password query</p>
    "! @parameter r_result | <p class="shorttext synchronized" lang="en"></p>
    CLASS-METHODS create
      RETURNING VALUE(r_result) TYPE REF TO zif_pwned_passwords.

    METHODS constructor
      IMPORTING
        ir_api_call TYPE REF TO zif_pwned_passwords_api_call.
  PROTECTED SECTION.
    "! <p class="shorttext synchronized" lang="en">Hashes the password in preparation for API call</p>
    "! @parameter i_password | <p class="shorttext synchronized" lang="en">Password</p>
    "! @parameter r_result | <p class="shorttext synchronized" lang="en">Hash of password</p>
    METHODS hash_password
      IMPORTING
        i_password      TYPE string
      RETURNING
        VALUE(r_result) TYPE string
      RAISING
        zcx_pwned_passwords.
  PRIVATE SECTION.
    DATA api_wrapper TYPE REF TO zif_pwned_passwords_api_call.
ENDCLASS.



CLASS zcl_pwned_passwords IMPLEMENTATION.
  METHOD constructor.
    IF ir_api_call IS NOT BOUND.
      RAISE EXCEPTION TYPE cx_parameter_invalid
        EXPORTING
          parameter = 'IR_API_CALL'.
    ENDIF.

    me->api_wrapper = ir_api_call.
  ENDMETHOD.

  METHOD hash_password.
    DATA raw_password TYPE xstring.

    TRY.
        " Generate SHA1 hash of password
        DATA(converter) = cl_abap_conv_out_ce=>create( ).
        converter->convert(
             EXPORTING
               data   = i_password
             IMPORTING
               buffer = raw_password ).

        DATA(digest) = cl_abap_message_digest=>get_instance( 'sha1' ).
        digest->update( if_data = raw_password ).
        digest->digest( ).

        r_result = digest->to_string( ).
      CATCH cx_abap_message_digest cx_sy_codepage_converter_init
            cx_sy_conversion_codepage cx_parameter_invalid_type INTO DATA(ex).

        RAISE EXCEPTION TYPE zcx_pwned_passwords
          EXPORTING
            previous = ex
            textid   = zcx_pwned_passwords=>internal_error.
    ENDTRY.
  ENDMETHOD.


  METHOD zif_pwned_passwords~is_password_pwned.
    r_result = me->zif_pwned_passwords~get_password_status( i_password = i_password )-result.
  ENDMETHOD.


  METHOD zif_pwned_passwords~get_password_status.
    r_result = VALUE #( result = abap_false count = 0 ).

    CHECK i_password IS NOT INITIAL. " Blank is not pwned

    DATA(hash) = to_upper( me->hash_password( i_password = i_password ) ).

    " Pwned Passwords API wants the 1st 5 characters of the hash
    DATA(hash_prefix) = hash(5).

    me->api_wrapper->query_pwned_passwords_api(
      EXPORTING
        i_hash_prefix       = hash_prefix
      IMPORTING
        et_password_hashes  = DATA(hashes) ).

    " Find the matching hash line -> : splits hash and password count
    LOOP AT hashes ASSIGNING FIELD-SYMBOL(<hash>).
      CHECK strlen( <hash> ) >= 35.
      DATA(full_hash) = hash_prefix && <hash>(35). " SHA1 -> 40 chars
      CHECK full_hash = hash.

      SPLIT <hash> AT ':' INTO TABLE DATA(hash_split).

      IF lines( hash_split ) <> 2.
        RAISE EXCEPTION TYPE zcx_pwned_passwords
          EXPORTING
            textid = zcx_pwned_passwords=>malformed_api_response.
      ENDIF.

      r_result = VALUE #( result = abap_true count = hash_split[ 2 ] ).
      RETURN.
    ENDLOOP.
  ENDMETHOD.

  METHOD create.
    r_result = NEW zcl_pwned_passwords( NEW zcl_pwned_passwords_api_call( ) ).
  ENDMETHOD.
ENDCLASS.
