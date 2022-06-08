import msg_pb2


def update_protobuf(proto_obj=None, update_dict:dict=None):
	"""
	update the given protobuf object `obj` with the given dict `update_dict`.
	throw an exception in case of an error. if `update_dict` is None, use the
	default
	@arg obj - the protobuf object to update
	@arg update_dict - the dict used to update `obj`
	@return updated protobuf object
	"""
	#TODO define update_dict defaults in a different module
	if proto_obj is None or update_dict is None:
		print(f':. arguments to update_protobuf cannot be None')
		return
	try:
		def update(obj, d):
			for key, val in d.items():
				if isinstance(val, dict):
					update(getattr(obj, key), val)
				else:
					setattr(obj, key, val)
		update(proto_obj, update_dict)
	except Exception as e:
		print(f':. error while updating protobuf {e}')
		raise e


class defaults:
	
	CompanionPropsSpec = {
		'os': 'Mac OS',
		'version': {
			'primary': 10,
			'secondary': 15,
			'tertiary': 7
		},
		'requireFullSync': False,
		'platformType': 1
	}

	ClientPayloadSpec = {
		'connectReason': 1,
		'connectType': 1,
		'webInfo': {
			'webSubPlatform': 0
		},
		'userAgent': {
			'platform': 14,
			'osVersion': "0.1",
			'releaseChannel': 0,
			'osBuildNumber': "0.1",
			'mnc': "000",
			'mcc': "000",
			'manufacturer': "",
			'localeCountryIso31661Alpha2': "GB",
			'localeLanguageIso6391': "en",
			'device': "Desktop",
			'appVersion': {
				'primary': 2,
				'secondary': 2220,
				'tertiary': 8
			}
		},	
		'devicePairingData': {
			'eKeytype': b'\x05'
		}
	}





