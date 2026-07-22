# Hardware Notes — RBX-S73

Only proceed to hardware work if software investigation is inconclusive.
**Avoid irreversible changes; back up flash before writing anything.**

## Safety rules (from CLAUDE.md)
- Determine UART voltage **before** attaching an adapter (expect 3.3 V).
- Use a 3.3 V USB-UART adapter. **Do not connect VCC.**
- Connect Ground, Camera TX → adapter RX; connect adapter TX → Camera RX only
  when input is needed.
- Back up flash before any write. Have a recovery plan.

## Board survey (photograph everything)
| Item | Finding |
|------|---------|
| SoC marking | _TBD_ |
| Flash chip (part #, type NOR/NAND) | _TBD_ |
| RAM | _TBD_ |
| Wi-Fi module | _TBD_ |
| UART pads (labeled?) | _TBD_ |
| Other test pads / JTAG | _TBD_ |

## UART bring-up
- Measured TX idle voltage: _TBD_
- Baud (try 115200, 57600, 38400, 9600): _TBD_
- Boot log highlights (bootloader, kernel, filesystem): _TBD_
- Shell available? root? bootloader interrupt? : _TBD_

## Flash access options (least invasive first)
- [ ] Bootloader commands
- [ ] UART shell dump
- [ ] SPI flash clip (in-circuit)
- [ ] NAND removal
- [ ] Vendor recovery mode
