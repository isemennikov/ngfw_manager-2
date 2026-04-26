import logging

logger = logging.getLogger("parser")

def safe_get_action(item: dict) -> str:
    """РћС‡РёС‰Р°РµС‚ РїРѕР»Рµ action"""
    raw = item.get("action")
    if not raw: return "deny"
    if isinstance(raw, dict): raw = raw.get("name", "deny")
    s_raw = str(raw).upper()
    if "ALLOW" in s_raw or "PASS" in s_raw: return "allow"
    return "deny"

def parse_complex_object(data_block: dict, kind="ip") -> tuple[str, str]:
    """
    РџР°СЂСЃРёС‚ РѕР±СЉРµРєС‚С‹ Р»СЋР±РѕР№ РІР»РѕР¶РµРЅРЅРѕСЃС‚Рё.
    Р’РѕР·РІСЂР°С‰Р°РµС‚ (ShortText, TooltipText).
    """
    if not data_block or not isinstance(data_block, dict):
        return "Any", "Any"

    # 1. РџСЂРѕРІРµСЂСЏРµРј РЅР° Any
    kind_str = data_block.get("kind", "")
    if "ANY" in kind_str:
        return "Any", "Any"

    # 2. РџРѕР»СѓС‡Р°РµРј СЃРїРёСЃРѕРє РѕР±СЉРµРєС‚РѕРІ
    objects = data_block.get("objects", [])
    if not objects:
        return "Any", "Any"

    found_items = [] # РЎРїРёСЃРѕРє РєРѕСЂС‚РµР¶РµР№ (Display Name, Value)

    for wrapper in objects:
        # Р РµРєСѓСЂСЃРёРІРЅРѕ РёР·РІР»РµРєР°РµРј Р·РЅР°С‡РµРЅРёСЏ
        extracted = _extract_recursive(wrapper, kind)
        found_items.extend(extracted)

    if not found_items:
        return "Any", "Any"

    # 3. Р¤РѕСЂРјРёСЂСѓРµРј РІС‹РІРѕРґ
    short_tokens = []
    full_lines = []

    for name, val in found_items:
        # Р”Р»СЏ С‚Р°Р±Р»РёС†С‹: Р•СЃР»Рё РµСЃС‚СЊ РёРјСЏ, Р±РµСЂРµРј РёРјСЏ. Р•СЃР»Рё РЅРµС‚ - Р·РЅР°С‡РµРЅРёРµ.
        display = name if name else val
        short_tokens.append(display)
        
        # Р”Р»СЏ С‚СѓР»С‚РёРїР°: РРјСЏ (Р—РЅР°С‡РµРЅРёРµ)
        if name and val and name != val:
            full_lines.append(f"{name} ({val})")
        else:
            full_lines.append(val)

    # РћР±СЂРµР·Р°РµРј РґР»СЏ С‚Р°Р±Р»РёС†С‹, РµСЃР»Рё СЃР»РёС€РєРѕРј РјРЅРѕРіРѕ
    short_str = ", ".join(short_tokens)
    if len(short_str) > 30:
        short_str = short_str[:27] + "..."

    return short_str, "\n".join(full_lines)

def _extract_recursive(item: dict, kind: str) -> list:
    """
    Р РµРєСѓСЂСЃРёРІРЅРѕ РёС‰РµС‚ IP/Service РІРЅСѓС‚СЂРё СЃР»РѕР¶РЅРѕР№ СЃС‚СЂСѓРєС‚СѓСЂС‹.
    Р’РѕР·РІСЂР°С‰Р°РµС‚ СЃРїРёСЃРѕРє [(Name, Value), ...]
    """
    results = []
    
    # 1. РЎРЅРёРјР°РµРј РѕР±РµСЂС‚РєСѓ (networkIpAddress, service, networkGroup Рё С‚.Рґ.)
    # API С‡Р°СЃС‚Рѕ Р·Р°РІРѕСЂР°С‡РёРІР°РµС‚ РѕР±СЉРµРєС‚ РІ РєР»СЋС‡ СЃ РµРіРѕ С‚РёРїРѕРј
    inner = item
    keys_to_unwrap = ["networkIpAddress", "service", "application", "networkGroup", "serviceGroup", "portGroup"]
    
    for k in keys_to_unwrap:
        if k in item:
            inner = item[k]
            break
            
    # 2. РџРѕРїС‹С‚РєР° РёР·РІР»РµС‡СЊ РєРѕРЅРµС‡РЅРѕРµ Р·РЅР°С‡РµРЅРёРµ
    name = inner.get("name") or inner.get("display_name")
    val = None
    
    if kind == "ip":
        val = inner.get("inet") or inner.get("ipv4") or inner.get("subnet")
    elif kind == "service":
        proto = inner.get("protocol")
        if isinstance(proto, dict): proto = proto.get("name")
        port = inner.get("port")
        if not port and "singlePort" in inner: port = inner["singlePort"].get("port")
        
        if port: val = f"{proto}/{port}"
        elif proto: val = str(proto)

    if val:
        results.append((name, val))
        return results

    # 3. Р•СЃР»Рё Р·РЅР°С‡РµРЅРёСЏ РЅРµС‚, РїСЂРѕРІРµСЂСЏРµРј РІР»РѕР¶РµРЅРЅС‹Рµ РѕР±СЉРµРєС‚С‹ (Р“СЂСѓРїРїС‹)
    children = inner.get("objects") or inner.get("items") or inner.get("values")
    if children and isinstance(children, list):
        for child in children:
            results.extend(_extract_recursive(child, kind))
            
    # 4. Р•СЃР»Рё СЌС‚Рѕ РїСѓСЃС‚Р°СЏ РіСЂСѓРїРїР° РёР»Рё РјС‹ РЅРµ РЅР°С€Р»Рё Р·РЅР°С‡РµРЅРёР№, РЅРѕ РµСЃС‚СЊ РёРјСЏ - РІРѕР·РІСЂР°С‰Р°РµРј РРјСЏ
    if not results and name:
        results.append((name, ""))
        
    return results
