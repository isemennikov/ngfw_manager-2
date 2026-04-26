import asyncio
import httpx
import json

# --- РљРћРќР¤РР“РЈР РђР¦РРЇ ---
BASE_URL = "https://ptsu.mriya.me"
LOGIN = "ptmt"          # <--- Р’РђРЁ Р›РћР“РРќ
PASSWORD = "..."        # <--- Р’РђРЁ РџРђР РћР›Р¬ (РІСЃС‚Р°РІСЊС‚Рµ СЃСЋРґР°)
# --------------------

async def test_create_rule():
    async with httpx.AsyncClient(verify=False, timeout=20.0, follow_redirects=True) as client:
        print(f"1. Logging in to {BASE_URL}...")
        
        # LOGIN
        try:
            resp = await client.post(f"{BASE_URL}/api/v2/Login", json={"login": LOGIN, "password": PASSWORD})
            if resp.status_code != 200:
                print(f"Login Failed: {resp.text}")
                return
            
            cookie = resp.headers.get("grpc-metadata-set-cookie") or resp.headers.get("set-cookie")
            token = cookie.split(";")[0]
            print("   Login OK. Token received.")
            
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Cookie": token
            }
        except Exception as e:
            print(f"Login Error: {e}")
            return

        # GET GROUPS (To get a valid Device Group ID)
        print("2. Getting Device Group ID...")
        resp = await client.post(f"{BASE_URL}/api/v2/GetDeviceGroupsTree", headers=headers, json={})
        groups = resp.json().get("groups", [])
        if not groups:
            print("   No groups found!")
            return
        
        gid = groups[0]["id"] # Р‘РµСЂРµРј РїРµСЂРІСѓСЋ РїРѕРїР°РІС€СѓСЋСЃСЏ РіСЂСѓРїРїСѓ
        print(f"   Using Group ID: {gid}")

        # VARIATIONS TO TRY
        # РњС‹ РїСЂРѕР±СѓРµРј СЂР°Р·РЅС‹Рµ С„РѕСЂРјР°С‚С‹ РїРѕР»СЏ 'objects' Рё 'sourceZone'
        
        variations = [
            {
                "name": "PAYLOAD_1_SIMPLE_LIST",
                "desc": "Objects as simple empty list []",
                "payload": {
                    "sourceZone": {"kind": "RULE_KIND_ANY", "objects": []},
                    "sourceAddr": {"kind": "RULE_KIND_ANY", "objects": []}
                }
            },
            {
                "name": "PAYLOAD_2_WRAPPER",
                "desc": "Objects with wrapper {'array': []}",
                "payload": {
                    "sourceZone": {"kind": "RULE_KIND_ANY", "objects": {"array": []}},
                    "sourceAddr": {"kind": "RULE_KIND_ANY", "objects": {"array": []}}
                }
            },
            {
                "name": "PAYLOAD_3_NULL",
                "desc": "Objects as None/null",
                "payload": {
                    "sourceZone": {"kind": "RULE_KIND_ANY", "objects": None},
                    "sourceAddr": {"kind": "RULE_KIND_ANY", "objects": None}
                }
            },
            {
                "name": "PAYLOAD_4_NO_KIND",
                "desc": "Just empty list without kind",
                "payload": {
                    "sourceZone": [],
                    "sourceAddr": []
                }
            },
            {
                "name": "PAYLOAD_5_MINIMAL",
                "desc": "Minimal fields only",
                "payload": {} # РћСЃС‚Р°Р»СЊРЅС‹Рµ РїРѕР»СЏ РґРѕР±Р°РІР»СЏСЋС‚СЃСЏ РЅРёР¶Рµ
            }
        ]

        print("\n3. STARTING PAYLOAD TESTS...")
        
        for v in variations:
            print(f"\n--- Trying {v['name']} ({v['desc']}) ---")
            
            # Base body
            body = {
                "name": f"TEST_RULE_{v['name']}",
                "deviceGroupId": gid,
                "precedence": "RULE_PRECEDENCE_PRE",
                "action": "SECURITY_RULE_ACTION_ALLOW",
                "enabled": False,
                "logMode": "SECURITY_RULE_LOG_MODE_AT_RULE_HIT"
            }
            
            # Merge variation
            if v['name'] == "PAYLOAD_5_MINIMAL":
                # Р’ РјРёРЅРёРјР°Р»СЊРЅРѕРј РЅРµ РѕС‚РїСЂР°РІР»СЏРµРј Р·РѕРЅС‹ РІРѕРѕР±С‰Рµ, РµСЃР»Рё API РїРѕР·РІРѕР»СЏРµС‚
                pass 
            else:
                # Р—Р°РїРѕР»РЅСЏРµРј РІСЃРµ РїРѕР»СЏ РІС‹Р±СЂР°РЅРЅРѕР№ СЃС‚СЂСѓРєС‚СѓСЂРѕР№
                struct = v['payload']
                # Р•СЃР»Рё РІ РІР°СЂРёР°С†РёРё С‚РѕР»СЊРєРѕ 2 РїРѕР»СЏ, РєРѕРїРёСЂСѓРµРј РёС… РґР»СЏ РѕСЃС‚Р°Р»СЊРЅС‹С…
                obj_struct = struct.get("sourceAddr", [])
                
                body["sourceZone"] = struct.get("sourceZone", obj_struct)
                body["destinationZone"] = struct.get("sourceZone", obj_struct)
                
                body["sourceAddr"] = obj_struct
                body["destinationAddr"] = obj_struct
                body["service"] = obj_struct
                body["application"] = obj_struct
                body["urlCategory"] = obj_struct
                
                # User РІСЃРµРіРґР° РѕС‚Р»РёС‡Р°РµС‚СЃСЏ
                body["sourceUser"] = {"kind": "RULE_USER_KIND_ANY", "objects": []}

            # Wrap in "rule"
            final_payload = {"rule": body}
            
            try:
                r = await client.post(f"{BASE_URL}/api/v2/CreateSecurityRule", headers=headers, json=final_payload)
                print(f"   Status: {r.status_code}")
                if r.status_code == 200:
                    print(f"   SUCCESS! Response: {r.json()}")
                    print(f"   >>> WINNER IS: {v['name']} <<<")
                    
                    # Cleanup
                    new_id = r.json().get("rule", {}).get("id")
                    if new_id:
                        print("   Cleaning up (Deleting)...")
                        await client.post(f"{BASE_URL}/api/v2/DeleteSecurityRule", headers=headers, json={"id": new_id})
                    break
                else:
                    print(f"   Failed. Resp: {r.text[:200]}")
            except Exception as e:
                print(f"   Exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_create_rule())
