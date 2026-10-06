from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CharacterAccessoryOwnershipTests(unittest.TestCase):
    def test_accessories_preserve_weapons_and_repair_persisted_bad_owners(self):
        code = r'''
import copy
import assaultfire_server_v143b as s

s._v140_select_player(10001)
role = s._v140_current_role_gid()
bag = s._v141_current_bag_gid()
weapon_ids = {100497, 100009, 100058, 100010}
weapons = {int(p['gid']): copy.deepcopy(p) for p in s.V111_INVENTORY
           if p['item_id'] in weapon_ids}
sofia_hair = s._v140_find_prop(s.V129_SOFIA_HAIR_GID)
assert sofia_hair['owner_gid'] == role and sofia_hair['location'] == s.V129_LOC_HAIR
assert s.V173_CHARACTER_BUNDLE_COMPONENT_ROLE_ITEMS[100602] == frozenset((100600,))
assert s.V173_CHARACTER_BUNDLE_COMPONENT_ROLE_ITEMS[100601] == frozenset((100599,))

def make(item_id):
    prop = s._v140_make_prop(s._v140_next_gid(), item_id)
    s.V111_INVENTORY.append(prop)
    return prop

def equip(prop, target, location):
    return s._v111_apply_prop_operation(dict(operation=s.PROP_OP_EQUIP,
        subject_gid=prop['gid'], target_gid=target, location=location))

# Replay the reported cap, glasses and waist-pouch requests. A generic storage
# location must become a character socket, not a backpack weapon socket.
accessories = [make(item_id) for item_id in (100609, 100610, 100611)]
for prop, requested, slot in zip(accessories, (12, 1, 2), (0, 1, 2)):
    action, effective = equip(prop, role, requested)
    assert prop['owner_gid'] == role and prop['location'] == slot
    assert effective['target_gid'] == role and effective['location'] == slot
    assert 'accessory equip' in action
    assert len(s._v111_pack_prop_operation(effective)) == 19
assert sofia_hair['owner_gid'] == role and sofia_hair['location'] == s.V129_LOC_HAIR
assert all(s._v140_find_prop(gid) == prop for gid, prop in weapons.items())

# A purchased character bundle's hair stays mounted when headwear is equipped.
angela_bundle = s._v140_build_commodity_props(200592)
s.V111_INVENTORY.extend(angela_bundle)
angela_role, _, _, angela_hair = angela_bundle
angela_hat = make(100609)
equip(angela_hat, angela_role['gid'], 12)
assert angela_hair['owner_gid'] == angela_role['gid'] and angela_hair['location'] == 0
assert s._v173_is_character_bundle_component(angela_hair)

# Wrong explicit socket and backpack targets cannot turn a hat into a gun.
_, effective = equip(accessories[0], bag, 3)
assert effective['target_gid'] == role and effective['location'] == 0

# Equal socket numbers are exclusive within each character independently.
second_role = make(100458)
second_hat = make(100609)
equip(second_hat, second_role['gid'], 12)
assert accessories[0]['owner_gid'] == role
equip(second_hat, role, 12)
assert accessories[0]['owner_gid'] == 0 and accessories[0]['location'] == 12
assert second_hat['owner_gid'] == role
s._v111_apply_prop_operation(dict(operation=s.PROP_OP_TAKEOFF,
    subject_gid=second_hat['gid'], target_gid=0, location=0))
assert second_hat['owner_gid'] == 0 and second_hat['location'] == 12

# Persist the old broken attachments and a hair component displaced by
# the old slot-exclusivity behavior, then verify login repairs both.
for prop, slot in zip(accessories, (0, 1, 2)):
    prop.update(owner_gid=bag, location=slot)
sofia_hair.update(owner_gid=0, location=s.V109_LOC_BAG)
s._v140_save_state('test-corrupt-accessory-owners')
before = copy.deepcopy(list(s.V111_INVENTORY))
wallet = copy.deepcopy(s._v140_wallet())
s._V140_PLAYER_STATE._cache.pop(10001, None)
s._v140_select_player(10001)
saved = s.PLAYER_DB.load_player_state(10001)
assert len(saved['inventory']) == len(before)
assert saved['wallet'] == wallet
for prop in accessories:
    repaired = s._v140_find_prop(prop['gid'])
    assert repaired['owner_gid'] == 0 and repaired['location'] == 12
    assert any(p['gid'] == prop['gid'] and p['owner_gid'] == 0 for p in saved['inventory'])
    old = next(p for p in before if p['gid'] == prop['gid'])
    assert {k:v for k,v in repaired.items() if k not in ('owner_gid', 'location')} == {
        k:v for k,v in old.items() if k not in ('owner_gid', 'location')}
restored_hair = s._v140_find_prop(sofia_hair['gid'])
assert restored_hair['owner_gid'] == role and restored_hair['location'] == s.V129_LOC_HAIR
assert any(
    p['gid'] == sofia_hair['gid'] and p['owner_gid'] == role
    and p['location'] == s.V129_LOC_HAIR for p in saved['inventory']
)
assert all(s._v140_find_prop(gid) == prop for gid, prop in weapons.items())
once = copy.deepcopy(list(s.V111_INVENTORY))
s._v140_select_player(10001)
assert list(s.V111_INVENTORY) == once

# Correctly attached accessories remain attached on reload.
equip(s._v140_find_prop(accessories[0]['gid']), role, 12)
s._v140_save_state('test-valid-character-owner')
s._V140_PLAYER_STATE._cache.pop(10001, None)
s._v140_select_player(10001)
assert s._v140_find_prop(accessories[0]['gid'])['owner_gid'] == role

# Exercise the full PH accessory metadata while preserving weapon placement.
assert len(s.V173_CHARACTER_ACCESSORY_SLOTS) == 119
for item_id, slot in s.V173_CHARACTER_ACCESSORY_SLOTS.items():
    prop = make(item_id)
    _, effective = equip(prop, role, 12)
    assert effective['target_gid'] == role and effective['location'] == slot
assert all(s._v140_find_prop(gid) == prop for gid, prop in weapons.items())

# A waist bag is not a weapon backpack just because its display name says bag.
s.V140_COMMODITY_NAMES[999900] = 'American Waist Bag'
s.V140_COMMODITY_BUNDLES[999900] = (100611,)
assert 100611 not in s._v141_catalog_bag_item_ids()

# Weapon equip and exclusive backpack selection keep their existing behavior.
for item_id, slot in ((100497, 0), (100009, 1), (100058, 2), (100010, 3)):
    prop = make(item_id)
    _, effective = equip(prop, bag, 12)
    assert effective['target_gid'] == bag and effective['location'] == slot
for backpack in s._v141_bag_props():
    equip(backpack, 1, 12)
    assert sum(p['owner_gid'] == 1 for p in s._v141_bag_props()) == 1
print('PASS: character accessory ownership and persisted repair')
'''
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env.update(AF_ACCOUNT_DB=str(Path(td) / 'accounts.sqlite3'),
                       AF_RUNTIME_MODE='production', AF_DEV_WEB='0')
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT/'server',
                                    env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: character accessory ownership', result.stdout)


if __name__ == '__main__':
    unittest.main()
