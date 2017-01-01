# Usage
firm_builder [output file] [arm9 entry addr] [arm11 entry addr] [section0 loading addr] [section0 copy method] [section0 binary] [section1 loading addr] ...

# Notes
* The minimum section count is 1, the maximum is 4.
* Sections will be aligned to 0x200-bytes automatically.
