# Klingel

Raspberry Pi based SIP doorbell module. This program allows to hook up a Raspberry Pi to a classical door bell/door opener system and SIP capable telephone system (such as a [Fritz Box](https://en.avm.de/products/fritzbox/)).

It can:
* respond to the door bell button
* ring an external door bell
* call a pre-specified phone number via SIP
* connect an external intercom system to the phone call
* actuate a door buzzer via a PIN code during the call or through a web interface

The SIP capability is provided by the excellent [PJSIP](https://www.pjsip.org/) library.
