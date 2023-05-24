#!/bin/bash
#

pushd /home/dank/mailbox/dcloud_srv

scp dankmail@dcloud:/mailbox/outgoing/* ./.tmp

msg_cnt=$(ls -1 ./.tmp | wc -l);
if [ $msg_cnt -gt 0 ]; then
	scp ./.tmp/* dankmail@dcloud:/mailbox/confirm_recv/
	mv ./.tmp/* .
	aplay -q /usr/share/sounds/freedesktop/stereo/message-new-instant.wav
	notify-send --icon=mail-inbox "Cloud Server" "${msg_cnt} New message(s) received from Dank Cloud Server"
fi;

