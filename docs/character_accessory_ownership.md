# Character accessory ownership (PH 1.0.0.24)

Equipping the American cap, glasses or waist pouch previously placed their icons
in weapon slots and displaced the equipped guns. The A008 request targeted the
character, but the generic equipment path fell back to the current backpack.
Character and backpack sockets both use numbers 0, 1 and 2; ownership determines
whether they represent accessories or weapons.

The server now uses the PH item library's `MainShowType=1` and
`Location=0/1/2/7` metadata to identify 119 character accessories. Accessory equip
targets an owned character root and uses its canonical character socket. A
generic storage location or wrong explicit location cannot route it into a
weapon slot. Socket exclusivity applies only between standalone accessories on the
same character. Character bundle components, including the default hair
parts, stay attached when a head accessory uses the same numeric socket. Login
repairs bundle components that an earlier build moved into storage, restoring
the component to its matching character root. Normal weapon equip,
character-root selection, accessory takeoff and backpack selection retain their
existing paths. Accessory names containing “bag” cannot classify a waist pouch
as a weapon backpack.

On player load, accessories incorrectly mounted on backpacks or literal root
owner 1 return to storage and persist through the existing SQLite transaction.
Correct character mounts, item records, expiry, durability, wallet and weapon
placement are preserved. Re-equip repaired accessories on the character and any
weapons previously displaced by the old bug. The repair does not guess which
stored weapon should occupy a bag slot.

This change requires a server restart. It does not require the expanded mall
package or change catalog visibility, prices, translations or client assets.

Regression tests replay the reported A008 forms, check all accessory metadata,
verify per-character exclusivity and weapon/backpack behavior, and reload both
broken and valid attachments from isolated SQLite. Live Windows appearance
rendering still needs an in-game check.
