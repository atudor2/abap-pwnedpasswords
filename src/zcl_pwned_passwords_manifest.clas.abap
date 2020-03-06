CLASS zcl_pwned_passwords_manifest DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.
    INTERFACES zif_apack_manifest.
    methods constructor.
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.

CLASS zcl_pwned_passwords_manifest IMPLEMENTATION.
  METHOD constructor.
    me->zif_apack_manifest~descriptor = value #(
        group_id    = 'github.com/atudor2'
        artifact_id = 'abap-pwnedpasswords'
        version     = '0.3'
        git_url     = 'https://github.com/atudor2/abap-pwnedpasswords.git'
    ).
  ENDMETHOD.
ENDCLASS.
