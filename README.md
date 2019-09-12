# greetd

Generic display manager. Composed of a daemon which:

1. Launches a greeter of your choice.
2. Listens on a socket for a login message.
3. If the credentials are valid, terminates the greeter and starts the requested session application.
4. When the session application terminates, the greeter is started once again.

All the greeter of choice needs to do is to be able to write a message to a socket. It could be anything from a simple terminal application to a fully-fledged desktop environment in which one of the applications present a user prompt.

The greeter runs as a configured user, which is supposed to be one with no interesting privileges except for what the greeter itself needs to run.

Future plans involve adding lock-screen support.

Protocol subject to change soon.

## Included in the box:

1. greetd, the daemon itself
2. greetctl, a sample application to issue the login message.

## Dumb demo

1. echo "exec alacritty" > /tmp/sway-lm-config
2. sudo greetd --vt 4 --greeter "sway --config /tmp/sway-lm-config" --greeter-user $LOGNAME
3. (In the new terminal): greetctl
4. Answer the questions, and the sway greeter will be replaced by whatever you typed if your login is successful.

## It doesn't work yet!

Why are you using this? I haven't even tested it myself!