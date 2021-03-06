"! <p class="shorttext synchronized" lang="en">Pwned Passwords Exception</p>
CLASS zcx_pwned_passwords DEFINITION
  PUBLIC
  INHERITING FROM cx_static_check
  CREATE PUBLIC .

  PUBLIC SECTION.
    INTERFACES if_t100_dyn_msg .
    INTERFACES if_t100_message .
    DATA:
       additional_message TYPE string READ-ONLY.

    CONSTANTS:
      BEGIN OF malformed_api_response,
        msgid TYPE symsgid VALUE 'ZPWNEDPASS_EXCEPTION',
        msgno TYPE symsgno VALUE '001',
        attr1 TYPE scx_attrname VALUE '',
        attr2 TYPE scx_attrname VALUE '',
        attr3 TYPE scx_attrname VALUE '',
        attr4 TYPE scx_attrname VALUE '',
      END OF malformed_api_response,
      BEGIN OF internal_error,
        msgid TYPE symsgid VALUE 'ZPWNEDPASS_EXCEPTION',
        msgno TYPE symsgno VALUE '002',
        attr1 TYPE scx_attrname VALUE 'ADDITIONAL_MESSAGE',
        attr2 TYPE scx_attrname VALUE '',
        attr3 TYPE scx_attrname VALUE '',
        attr4 TYPE scx_attrname VALUE '',
      END OF internal_error,
      BEGIN OF network_error,
        msgid TYPE symsgid VALUE 'ZPWNEDPASS_EXCEPTION',
        msgno TYPE symsgno VALUE '003',
        attr1 TYPE scx_attrname VALUE 'ADDITIONAL_MESSAGE',
        attr2 TYPE scx_attrname VALUE '',
        attr3 TYPE scx_attrname VALUE '',
        attr4 TYPE scx_attrname VALUE '',
      END OF network_error .

    "! <p class="shorttext synchronized" lang="en">CONSTRUCTOR</p>
    METHODS constructor
      IMPORTING
        textid             LIKE if_t100_message=>t100key OPTIONAL
        previous           LIKE previous OPTIONAL
        additional_message TYPE string OPTIONAL.
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.
CLASS zcx_pwned_passwords IMPLEMENTATION.
  METHOD constructor ##ADT_SUPPRESS_GENERATION.
    CALL METHOD super->constructor
      EXPORTING
        previous = previous.
    CLEAR me->textid.
    IF textid IS INITIAL.
      if_t100_message~t100key = if_t100_message=>default_textid.
    ELSE.
      if_t100_message~t100key = textid.
    ENDIF.

    me->additional_message = additional_message.
  ENDMETHOD.
ENDCLASS.
