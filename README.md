# PacketFu

[![Build Status](https://secure.travis-ci.org/packetfu/packetfu.png)](http://travis-ci.org/packetfu/packetfu)
[![Code Climate](https://codeclimate.com/github/packetfu/packetfu.png)](https://codeclimate.com/github/packetfu/packetfu)

A library for reading and writing packets to an interface or to a
libpcap-formatted file.

It is maintained [here](https://github.com/packetfu/packetfu).

## Documentation

PacketFu is yard-compatible (as well as sdoc/rdoc, if you prefer). You
can generate local documentation easily with either `yard doc .` or
`sdoc`, and view doc/index.html with your favored browser. Once that's
done, navigate at the top, and read up on how to create a Packet or
Capture from an interface with show_live or whatever.

## Setup

To install the gem, type

```bash
gem install packetfu
```

To install from source, type

```bash
gem install bundler
git clone https://github.com/packetfu/packetfu.git
cd packetfu
bundle install
```

## Supported Rubies

This project is integrated with travis-ci and is regularly tested to work with the following rubies:

- 2.1.6
- 2.2.3
- 2.3.0

To checkout the current build status for these rubies, click [here](https://travis-ci.org/packetfu/packetfu).

## Examples

PacketFu ships with dozens and dozens of tests, built on Test::Unit.
These should give good pointers on how you're expected to use it. See
the /tests directory. Furthermore, PacketFu also ships with
packetfu-shell.rb, which should be run via IRB (as root, if you intend
to use your interfaces).

## Author

PacketFu is maintained primarily by Tod Beardsley todb@packetfu.com and
Jonathan Claudius claudijd@yahoo.com, with help from Open Source Land.

See [LICENSE](https://github.com/packetfu/packetfu/blob/master/LICENSE.txt) for licensing details.
