"""Real test data: 8 firewall rules from production."""

# Actual rules data from NGFW
SAMPLE_RULES = [
    {
        'id': '019be530-75a0-7a6a-ba06-f658af91888e',
        'name': 'temp_opentelemetry_without_DPI',
        'description': '',
        'createdAt': '2026-01-22T10:11:56.960628Z',
        'updatedAt': '2026-02-17T16:03:46.681139Z',
        'deviceGroupId': '0197fb01-2707-79e8-95d1-70c78c6fd104',
        'precedence': 'post',
        'position': 59,
        'sourceZone': {'kind': 'RULE_KIND_ANY', 'objects': []},
        'sourceAddr': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'networkIpRange': {
                        'id': '019b0a0f-fdf8-70d0-a405-c6335dc9698c',
                        'name': 'r__10.31.67.144-148',
                        'description': '',
                        'deviceGroupId': '0197fb01-2707-79e8-95d1-70c78c6fd104',
                        'type': 'ipV4Range',
                        'from': '10.31.67.144',
                        'to': '10.31.67.148',
                        'createdAt': '2025-12-10T20:59:38.872007Z'
                    }
                },
                {
                    'networkIpRange': {
                        'id': '019c6c3e-3380-7ece-97bc-414e029b4f80',
                        'name': 'r__10.108.67.143-148',
                        'description': '',
                        'deviceGroupId': '0197fb01-2707-79e8-95d1-70c78c6fd104',
                        'type': 'ipV4Range',
                        'from': '10.108.67.143',
                        'to': '10.108.67.148',
                        'createdAt': '2026-02-17T15:35:41.696908Z'
                    }
                }
            ]
        },
        'sourceUser': {'kind': 'RULE_USER_KIND_ANY', 'objects': []},
        'destinationZone': {'kind': 'RULE_KIND_ANY', 'objects': []},
        'destinationAddr': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'networkIpRange': {
                        'id': '019aeace-4c28-74b8-84ce-f80ef1fd4ae1',
                        'name': 'r__10.43.16.0-.18.0',
                        'description': '',
                        'deviceGroupId': '0197fb01-2707-79e8-95d1-70c78c6fd104',
                        'type': 'ipV4Range',
                        'from': '10.43.16.0',
                        'to': '10.43.18.0',
                        'createdAt': '2025-12-04T19:19:39.816237Z'
                    }
                },
                {
                    'networkIpAddress': {
                        'id': '019adfad-dd3f-7e02-90cb-7cae9133accb',
                        'name': 'h__10.44.16.100',
                        'description': '',
                        'deviceGroupId': '0197fb01-2707-79e8-95d1-70c78c6fd104',
                        'type': 'ipV4Addr',
                        'inet': '10.44.16.100/32',
                        'createdAt': '2025-12-02T15:28:24.895865Z'
                    }
                }
            ]
        },
        'service': {
            'kind': 'RULE_KIND_LIST',
            'objects': [
                {
                    'service': {
                        'id': '019b0a0b-3eca-7ca4-9e2a-ca9f7950102c',
                        'name': 'tcp__4317-4318',
                        'description': '',
                        'deviceGroupId': '0197fb01-2707-79e8-95d1-70c78c6fd104',
                        'origin': 'custom',
                        'protocol': 'SERVICE_PROTOCOL_TCP',
                        'srcPorts': [],
                        'dstPorts': [{'portRange': {'from': 4317, 'to': 4318}}],
                        'createdAt': '2025-12-10T20:54:27.786781Z'
                    }
                }
            ]
        },
        'application': {'kind': 'RULE_KIND_ANY', 'objects': []},
        'urlCategory': {'kind': 'RULE_KIND_ANY', 'objects': []},
        'action': 'SECURITY_RULE_ACTION_ALLOW',
        'logMode': 'SECURITY_RULE_LOG_MODE_NO_LOG',
        'enabled': True,
        'schedule': {}
    }
]
