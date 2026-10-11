       >>SOURCE FORMAT FREE
identification division.
program-id. GUARD-GATE.
environment division.
configuration section.
repository. function all intrinsic.
data division.
working-storage section.
01 incoming pic x(512).
01 transfer-record.
   02 transfer-id pic x(36).
   02 amount-minor pic 9(12).
   02 currency-code pic x(3).
   02 recipient-id pic x(64).
   02 authorization-state pic x.
procedure division.
    accept incoming
    if function length(function trim(incoming trailing)) not = 116
        display 'REJECTED:LENGTH'
        move 2 to return-code
        goback
    end-if
    move incoming(1:116) to transfer-record
    if amount-minor is not numeric
        display 'REJECTED:AMOUNT'
        move 2 to return-code
        goback
    end-if
    if amount-minor = 0 or amount-minor > 100000000
        display 'REJECTED:LIMIT'
        move 2 to return-code
        goback
    end-if
    if currency-code not = 'BRL' and not = 'USD'
        and not = 'EUR'
        display 'REJECTED:CURRENCY'
        move 2 to return-code
        goback
    end-if
    if authorization-state not = 'A' or recipient-id = spaces
        display 'REJECTED:AUTHORIZATION'
        move 2 to return-code
        goback
    end-if
    if transfer-id(9:1) not = '-' or transfer-id(14:1) not = '-'
        or transfer-id(19:1) not = '-' or transfer-id(24:1) not = '-'
        display 'REJECTED:IDENTIFIER'
        move 2 to return-code
        goback
    end-if
    display 'ACCEPTED:' transfer-id ':' amount-minor ':' currency-code
    move 0 to return-code
    goback.
