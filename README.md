1. Type make to compile
2. If you plan to run the program as a receiver, first create a txt file, 
where the mails will be send, e.g. 'example.txt'. Then to run as receiver use:
./smtp -r [-f filename], where filename is 'example.txt'.
3. If you plan to run the program as a sender, first create a txt file with
already prepared mail you want to send to the receiver, e.g. 'example.txt'. To run
as a sender use: ./smtp -s [hostname] [-f filename], where filename is 'example.txt'.
Notice: you need to know your receiver's ip to be able to connect.

Assumptions:
- Choice of language: C
- Server is the receiver
- For the best performance follow scenario 1 exactly like it is mentioned 
in RFC 821. 
- The hostnames are substituted with the addresses.
- It is assumed that users: <Bill@hostname>, <Kevin@hostname> and <Tod@hostname>
are present on the receiver. 
- When receiver sends the code 354, sender should not input the mail, but
just type 'Send' to send the mail from the provided file.

Example of execution:

Sender:
The program runs in sender mode.
220 0.0.0.0 Simple Mail Transfer Service Ready
>>HELO 10.123.197.171
250 0.0.0.0
>>MAIL FROM:<Smith@10.123.197.171>
250 OK
>>RCPT TO:<Kevin@0.0.0.0>
250 OK
>>RCPT TO:<FF@0.0.0.0>
550 No such user here
>>RCPT TO:<Tod@0.0.0.0>
250 OK
>>RCPT TO:<AA@0.0.0.0>
550 No such user here
>>DATA
354 Start mail input; end with <CRLF>.<CRLF>
>>Send
250 OK
>>QUIT
221 0.0.0.0 Service closing transmission channel

Receiver:
The program runs in receiver mode.
HELO 10.123.197.171
MAIL FROM:<Smith@10.123.197.171>
RCPT TO:<Kevin@0.0.0.0>
RCPT TO:<FF@0.0.0.0>
RCPT TO:<Tod@0.0.0.0>
RCPT TO:<AA@0.0.0.0>
DATA
QUIT

