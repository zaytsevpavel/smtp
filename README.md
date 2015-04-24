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
- The hostnames are implemented as common names.
- It is assumed that users: <Bill@hostname>, <Kevin@hostname> and <Tod@hostname>
are present on the receiver. 
- When receiver sends the code 354, sender should not input the mail, but
just type 'Send' to send the mail from the provided file.
- The domain name of the emails you plan to send mails to is shown in the response after HELO command.
For example:
>>HELO pavels-macbook-air.local
250 Pavels-MacBook-Air.local
>>MAIL FROM:<Smith@pavels-macbook-air.local>
250 OK
>>RCPT TO:<Bill@Pavels-MacBook-Air.local>
250 OK

Example of execution:

The program runs in sender mode.
220 lvl-mm-mac-02.ics.usc.edu Simple Mail Transfer Service Ready
>>HELO pavels-macbook-air.local
250 lvl-mm-mac-02
>>MAIL FROM:<Smith@pavels-macbook-air.local>
250 OK
>>RCPT TO:<Bill@lvl-mm-mac-02>
250 OK
>>RCPT TO:<John@lvl-mm-mac-02>
550 No such user here
>>DATA
354 Start mail input; end with <CRLF>.<CRLF>
>>Send
250 OK
>>QUIT
