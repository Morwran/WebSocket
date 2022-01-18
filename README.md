### Websocket server

##### This is my own websocket server built in C language according to RFC 6455

#### Installation:
* make all (for release).
* make all TESTING=1 (for demo). In this case building demonstration version includes web server and a pattern generator for emulating SIN signal on server side and viewing real time graphics in the client browser.


#### Usage:
* [sudo] ./websocket [-p] [0 ... 65535]
* Where -p is a websocket port (usually 86)
