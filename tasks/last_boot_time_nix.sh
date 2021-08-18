#!/bin/sh

# Lifted from puppetlabs-reboot

# Try -F for time in seconds, fall back to without if unavailable
(last -1 -F reboot 2>/dev/null || last -1 reboot) | sed 's/\s-\s.*$//'