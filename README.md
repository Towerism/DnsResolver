# DnsResolver
HW Assignment 2 for CS463

# Building
Ensure that the `DnsResolver` project is the `Startup Project`. Otherwise make
sure that project `DnsResolver` is selected before you build.

# Report
The report pdf can be found in the `report` folder.

# Extra Errors
While running the program on `random4.irl` I noticed that the questions section
was previously unchecked for packet errors. So I introduced two extra errors:
- `++ query: truncated label length`, this will occur if the packet is only 12 bytes long
- `++ query: truncated label`, this will occur if the label length byte
  indicates that label is longer than there are bytes left in the packet

